'use strict';

(function ($) {
    $(function() {

        /**
         * @see ContactUs, Guest, SearchHistory, Selection, TwoFactorAuth.
         */

        /**
         * Get or create the spinner of a button, hidden by default.
         *
         * The spinner is appended inside a button or a link, and inserted after
         * an input, that cannot contain an element. It is created on load, so
         * it takes its place and the button is not resized when busy.
         */
        const spinnerOf = function (element) {
            const button = $(element);
            const isInput = button.is('input');
            let spinner = isInput ? button.next('span.spinner') : button.children('span.spinner');
            if (!spinner.length) {
                spinner = $('<span class="spinner fas fa-sync" aria-hidden="true"></span>');
                isInput ? spinner.insertAfter(button) : spinner.appendTo(button);
            }
            return spinner;
        };

        /**
         * Disable the button and display the spinner at the right of its label.
         */
        const beforeSpin = function (element) {
            spinnerOf(element).addClass('fa-spin');
            const button = $(element);
            button.is('button, input')
                ? button.prop('disabled', true)
                : button.attr('aria-disabled', 'true');
            button
                .attr('aria-busy', 'true')
                .addClass('is-busy');
        };

        const afterSpin = function (element) {
            spinnerOf(element).removeClass('fa-spin');
            const button = $(element);
            button.is('button, input')
                ? button.prop('disabled', false)
                : button.removeAttr('aria-disabled');
            button
                .removeAttr('aria-busy')
                .removeClass('is-busy');
        };

        $('#loginform [type=submit], #login-token-form [type=submit], .resend-code').each(function () {
            spinnerOf(this);
        });

        /**
         * Get the main message of jSend output, in particular for status fail.
         */
        const jSendMessage = function(data) {
            if (!data || typeof data !== 'object') {
                return null;
            }
            if (data.message) {
                return data.message;
            }
            if (!data.data) {
                return null;
            }
            for (let value of Object.values(data.data)) {
                if (typeof value === 'string' && value.length) {
                    return value;
                }
            }
            return null;
        }

        /**
         * Check if the response is a jSend output, not a html page.
         */
        const isJSend = function(data) {
            return data !== null && typeof data === 'object' && typeof data.status === 'string';
        }

        const dialogMessage = function (message, nl2br = false) {
            // Use a dialog to display a message, that should be escaped.
            var dialog = document.querySelector('dialog.popup-message');
            if (!dialog) {
                dialog = `
<dialog class="popup popup-dialog dialog-message popup-message" data-is-dynamic="1">
    <div class="dialog-background">
        <div class="dialog-panel">
            <div class="dialog-header">
                <button type="button" class="dialog-header-close-button">
                    <span class="dialog-close" aria-hidden="true">🗙</span>
                    <span class="dialog-close-label">${Omeka.jsTranslate('Close')}</span>
                </button>
            </div>
            <div class="dialog-contents">
                {{ message }}
            </div>
        </div>
    </div>
</dialog>`;
                $('body').append(dialog);
                dialog = document.querySelector('dialog.dialog-message');
            }
            if (nl2br) {
                message = message.replace(/(?:\r\n|\r|\n)/g, '<br/>');
            }
            dialog.innerHTML = dialog.innerHTML.replace('{{ message }}', message);
            dialog.showModal();
            $(dialog).trigger('o:dialog-opened');
        };

        /**
         * Go to the url set by the server after login, else reload the page.
         */
        const redirectAfterLogin = function(data) {
            if (data && data.data && data.data.redirect_url) {
                window.location.href = data.data.redirect_url;
            } else {
                window.location.reload();
            }
        };

        /**
         * Override submit of login form to manage optional login-token form.
         * @see Guest to manage the same login form in sites.
         */
        $(document).on('submit', '#loginform', function(ev) {
            ev.preventDefault();
            ev.stopImmediatePropagation();
            const form = $(this);
            const urlForm = form.attr('action') ? form.attr('action') : window.location.href;
            const submitButton = form.find('[type=submit]');
            $
                .ajax({
                    type: 'POST',
                    url: urlForm,
                    data: form.serialize(),
                    beforeSend: beforeSpin(submitButton),
                })
                .done(function(data) {
                    // The action is not an api endpoint, so submit it normally:
                    // a new login has no side effect.
                    if (!isJSend(data)) {
                        HTMLFormElement.prototype.submit.call(form[0]);
                        return;
                    }
                    // Success may be a single step login or a second step login.
                    if (data && data.data && data.data.login === true) {
                        redirectAfterLogin(data);
                        return;
                    }
                    // Success for first step, but require a second step. Always
                    // replace any existing dialog: the server-sent markup
                    // carries a fresh CSRF token and form state.
                    let dialog = document.querySelector('dialog.dialog-2fa-token');
                    const newDialog = data && data.data ? data.data.dialog : '';
                    if (newDialog) {
                        if (dialog) {
                            dialog.remove();
                        }
                        $('body').append(newDialog);
                        dialog = document.querySelector('dialog.dialog-2fa-token');
                    }
                    if (!dialog) {
                        let msg = jSendMessage(data);
                        dialogMessage(msg ? msg : Omeka.jsTranslate('Check input'), true);
                        return;
                    }
                    // The dialog is added after the load, so prepare its spinners now.
                    $(dialog).find('#login-token-form [type=submit], .resend-code').each(function () {
                        spinnerOf(this);
                    });
                    dialog.showModal();
                    $(dialog).trigger('o:dialog-opened');
                })
                .fail(function (xhr, textStatus, errorThrown) {
                    const data = xhr.responseJSON;
                    if (data && data.status === 'fail') {
                        // Fail is always an email/password error here.
                        let msg = jSendMessage(data);
                        dialogMessage(msg ? msg : Omeka.jsTranslate('Check input'), true);
                        form[0].reset();
                    } else {
                        // Error is a server error (in particular cannot send mail).
                        let msg = data && data.status === 'error' && data.message && data.message.length ? data.message : Omeka.jsTranslate('An error occurred.');
                        dialogMessage(msg, true);
                    }
                })
                .always(function () {
                    afterSpin(submitButton)
                });
        });

        /**
         * Manage the login-token form.
         */
        $(document).on('submit', '#login-token-form', function(ev) {
            ev.preventDefault();
            ev.stopImmediatePropagation();
            const form = $(this);
            const urlForm = form.attr('action') ? form.attr('action') : window.location.href;
            const submitButton = form.find('[type=submit]');
            $
                .ajax({
                    type: 'POST',
                    url: urlForm,
                    data: form.serialize(),
                    beforeSend: beforeSpin(submitButton),
                })
                .done(function(data) {
                    // Success may be a single step login or a second step login.
                    redirectAfterLogin(data);
                })
                .fail(function (xhr, textStatus, errorThrown) {
                    const data = xhr.responseJSON;
                    if (data && data.status === 'fail') {
                        // Fail is always an email/password or token error here.
                        let msg = jSendMessage(data);
                        dialogMessage(msg ? msg : Omeka.jsTranslate('Check input'), true);
                        form[0].reset();
                    } else {
                        // Error is a server error.
                        let msg = data && data.status === 'error' && data.message && data.message.length ? data.message : Omeka.jsTranslate('An error occurred.');
                        dialogMessage(msg, true);
                    }
                })
                .always(function () {
                    afterSpin(submitButton)
                });
        });

        $(document).on('click', '.resend-code', function(e) {
            // The button may be a button or a link: the link has the query in
            // the href, so skip the default navigation and always use ajax.
            e.preventDefault();
            const button = $(this);
            const urlButton = button.attr('data-url') ? button.attr('data-url') : button.attr('href');
            $
                .ajax({
                    type: 'GET',
                    url: urlButton,
                    data: {
                        resend_token: 1,
                        ajax: 1,
                    },
                    beforeSend: beforeSpin(button),
                })
                .done(function(data) {
                    let msg = jSendMessage(data);
                    dialogMessage(msg ? msg : 'A new code was resent.', true);
                })
                .fail(function (xhr, textStatus, errorThrown) {
                    const data = xhr.responseJSON;
                    // Error is a server error.
                    let msg = jSendMessage(data);
                    dialogMessage(msg ? msg : 'An error occurred.', true);
                })
                .always(function () {
                    afterSpin(button)
                });
        });

        $(document).on('click', '.dialog-header-close-button', function(e) {
            const dialog = this.closest('dialog.popup');
            if (dialog) {
                dialog.close();
                if (dialog.hasAttribute('data-is-dynamic') && dialog.getAttribute('data-is-dynamic')) {
                    dialog.remove();
                }
            } else {
                $(this).closest('.popup').addClass('hidden').hide();
            }
        });

    });
})(jQuery);
