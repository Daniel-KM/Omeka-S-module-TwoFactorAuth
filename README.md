Two-Factor Authentication (module for Omeka S)
==============================================

> __New versions of this module and support for Omeka S version 3.0 and above
> are available on [GitLab], which seems to respect users and privacy better
> than the previous repository.__

[Two-Factor Authentication] is a module for [Omeka S] that adds a security
mechanism with a second step to log in with a numeric code sent to user email.

The user can choose to enable it or not in the user settings, then a mail will
be sent on log in with a four digits check code.

The module is compatible with [Guest] and [User Names]. It is useless for other
authentication mechanisms ([CAS], [LDAP] or [Single Sign-On]), because they
should manage the second factor themselves.


Installation
------------

See general end user documentation for [installing a module].

This module requires the module [Common], that should be installed first.

* From the zip

Download the last release [TwoFactorAuth.zip] from the list of releases, and
uncompress it in the `modules` directory.

* From the source and for development

If the module was installed from the source, rename the name of the folder of
the module to `TwoFactorAuth`.

Then install it like any other Omeka module and follow the config instructions.


Quick start
-----------

An checkbox in user settings allows to enable/disable the two-factor
authentication.

When enabled, a mail is sent to the user with a four digits check code, that
must be pasted in the form to log in.


TODO
----

- [ ] Implement OTP to avoid mails.
- [ ] Limit the tokens to a small number to avoid brute force (see [Lockout]).
- [ ] Implement dialog for forgot password.


Warning
-------

Use it at your own risk.

It’s always recommended to backup your files and your databases and to check
your archives regularly so you can roll back if needed.


Troubleshooting
---------------

See online issues on the [module issues] page on GitLab.


License
-------

This module is published under the [CeCILL v2.1] license, compatible with
[GNU/GPL] and approved by [FSF] and [OSI].

This software is governed by the CeCILL license under French law and abiding by
the rules of distribution of free software. You can use, modify and/ or
redistribute the software under the terms of the CeCILL license as circulated by
CEA, CNRS and INRIA at the following URL "http://www.cecill.info".

As a counterpart to the access to the source code and rights to copy, modify and
redistribute granted by the license, users are provided only with a limited
warranty and the software’s author, the holder of the economic rights, and the
successive licensors have only limited liability.

In this respect, the user’s attention is drawn to the risks associated with
loading, using, modifying and/or developing or reproducing the software by the
user in light of its specific status of free software, that may mean that it is
complicated to manipulate, and that also therefore means that it is reserved for
developers and experienced professionals having in-depth computer knowledge.
Users are therefore encouraged to load and test the software’s suitability as
regards their requirements in conditions enabling the security of their systems
and/or data to be ensured and, more generally, to use and operate it in the same
conditions as regards security.

The fact that you are presently reading this means that you have had knowledge
of the CeCILL license and that you accept its terms.


Copyright
---------

* Copyright Daniel Berthereau, 2024 (see [Daniel-KM] on GitLab)

This module was built for the [digital library of Maison de Salins].


[Two-Factor Authentication]: https://gitlab.com/Daniel-KM/Omeka-S-module-TwoFactorAuth
[Omeka S]: https://omeka.org/s
[Guest]: https://gitlab.com/Daniel-KM/Omeka-S-module-Guest
[User Names]: https://github.com/ManOnDaMoon/omeka-s-module-UserNames
[CAS]: https://github.com/biblibre/omeka-s-module-CAS
[LDAP]: https://github.com/biblibre/omeka-s-module-Ldap
[Single Sign-On]: https://gitlab.com/Daniel-KM/Omeka-S-module-SingleSignOn
[Lockout]: https://gitlab.com/Daniel-KM/Omeka-S-module-Lockout
[installing a module]: https://omeka.org/s/docs/user-manual/modules
[TwoFactorAuth.zip]: https://github.com/Daniel-KM/Omeka-S-module-TwoFactorAuth/releases
[module issues]: https://gitlab.com/Daniel-KM/Omeka-S-module-TwoFactorAuth/issues
[Common]: https://gitlab.com/Daniel-KM/Omeka-S-module-Common
[CeCILL v2.1]: https://www.cecill.info/licences/Licence_CeCILL_V2.1-en.html
[GNU/GPL]: https://www.gnu.org/licenses/gpl-3.0.html
[FSF]: https://www.fsf.org
[OSI]: http://opensource.org
[digital library of Maison de Salins]: https://collections.maison-salins.fr
[GitLab]: https://gitlab.com/Daniel-KM
[Daniel-KM]: https://gitlab.com/Daniel-KM "Daniel Berthereau"
