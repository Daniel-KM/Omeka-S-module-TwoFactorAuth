'use strict';

(function ($) {
    $(document).ready(function() {

        /**
         * @see ContactUs, Selection, TwoFactorAuth.
         */

        const beforeSpin = function (element) {
            var span = $(element).find('span');
            if (!span.length) {
                span = $(element).next('span.appended');
                if (!span.length) {
                    $('<span class="appended"></span>').insertAfter($(element));
                    span = $(element).next('span');
                }
            }
            element.hide();
            span.addClass('fas fa-sync fa-spin');
        };

        const afterSpin = function (element) {
            var span = $(element).find('span');
            if (!span.length) {
                span = $(element).next('span.appended');
                if (span.length) {
                    span.remove();
                }
            } else {
                span.removeClass('fas fa-sync fa-spin');
            }
            element.show();
        };

        const dialogMessage = function (message, nl2br = false) {
            // Use a dialog to display a message, that should be escaped.
            var dialog = document.querySelector('dialog.popup-message');
            if (!dialog) {
                dialog = `
<dialog class="popup popup-dialog dialog-message popup-message" data-is-dynamic="1">
    <div class="dialog-background">
        <div class="dialog-panel">
            <div class="dialog-header">
                <button type="button" class="dialog-header-close-button" title="Close" autofocus="autofocus">
                    <span class="dialog-close">🗙</span>
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
        };

        /**
         * Override submit of login form to manage optional login-token form.
         */
        $(document).on('submit', '#loginform', function(ev) {
            ev.preventDefault();
            const form = $(this);
            const urlLogin = form.attr('action') ? form.attr('action') : window.location.href;
            const submitButton = form.find('[type=submit]');
            $
                .ajax({
                    type: 'POST',
                    url: urlLogin,
                    data: form.serialize(),
                    beforeSend: beforeSpin(submitButton),
                })
                .done(function(data) {
                    // Success may be a single step login or a second step login.
                    if (data.data && data.data.login === true) {
                        window.location.reload();
                        return;
                    }
                    // Success for first step, but require a second step.
                    // Use the existing dialog if any, else use the one sent.
                    let dialog = document.querySelector('dialog.dialog-login-token');
                    if (!dialog) {
                        dialog = data.data.dialog;
                        $('body').append(dialog);
                        dialog = document.querySelector('dialog.dialog-login-token');
                    }
                    dialog.showModal();
                })
                .fail(function (xhr, textStatus, errorThrown) {
                    const data = xhr.responseJSON;
                    if (data && data.status === 'fail') {
                        // Fail is always an email/password error here.
                        dialogMessage(data.data.message, true);
                        form[0].reset();
                    } else {
                        // Error is a server error (in particular cannot send mail).
                        let msg = data && data.status === 'error' && data.message && data.message.length ? data.message : 'An error occurred.';
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
            const form = $(this);
            const urlLogin = form.attr('action') ? form.attr('action') : window.location.href;
            const submitButton = form.find('[type=submit]');
            $
                .ajax({
                    type: 'POST',
                    url: urlLogin,
                    data: form.serialize(),
                    beforeSend: beforeSpin(submitButton),
                })
                .done(function(data) {
                    // Success may be a single step login or a second step login.
                    // Anyway, just reload the page.
                    window.location.reload();
                })
                .fail(function (xhr, textStatus, errorThrown) {
                    const data = xhr.responseJSON;
                    if (data && data.status === 'fail') {
                        // Fail is always an email/password or token error here.
                        let msg = data.data.token_email ? data.data.token_email : data.data.message ? data.data.message : 'Invalid code';
                        dialogMessage(msg, true);
                        form[0].reset();
                    } else {
                        // Error is a server error.
                        let msg = data && data.status === 'error' && data.message && data.message.length ? data.message : 'An error occurred.';
                        dialogMessage(msg, true);
                    }
                })
                .always(function () {
                    afterSpin(submitButton)
                });
        });

        $(document).on('click', '.resend-code', function(e) {
            // The button may be a button or a link.
            // The button is the ajax way; the link reloads the page.
            const button = $(this);
            const urlResend = button.attr('data-url-resend-code') ? button.attr('data-url-resend-code') : button.attr('href');
            if (button.element === 'A') {
                window.location.href = urlResend + '?resend_token=1';
                return;
            }
            $
                .ajax({
                    type: 'GET',
                    url: urlResend,
                    data: {
                        resend_token: 1,
                        ajax: 1,
                    },
                    beforeSend: beforeSpin(button),
                })
                .done(function(data) {
                    let msg = data.data.message ? data.data.message : 'A new code was resent.';
                    dialogMessage(msg, true);
                })
                .fail(function (xhr, textStatus, errorThrown) {
                    const data = xhr.responseJSON;
                    // Error is a server error.
                    let msg = data && data.status === 'error' && data.message && data.message.length ? data.message : 'An error occurred.';
                    dialogMessage(msg, true);
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
