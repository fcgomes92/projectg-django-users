=====
Users
=====

Users is a simple Django app to manage user login and register.
It uses Django's User Model or a custom User model.

Quick start
-----------

1. Add "users" to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = (
        ...
        'users',
    )

2. Include the Users URLconf in your project urls.py like this::

    url(r'^users/', include('users.urls')),

3. Set the dafault send email on the settings file like this::
	DJANGO_USERS_FROM_EMAIL = "contato@gmail.com"

4. If you hava a custom User Model set on the settings like this::
	AUTH_USER_MODEL = 'my.custom.UserModel'

5. Run `python manage.py migrate` to create the user models.

6. Start the development server and visit http://127.0.0.1:8000/user/
   to see the default login page.

7. Check the docs, or contact us, for custom settings.
