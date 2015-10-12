from django.conf import settings
from django.http import HttpResponseRedirect
from django.template import loader
from django.views.generic import FormView, View
from django.core.mail import send_mail
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.core.urlresolvers import reverse_lazy
from django.contrib.auth import logout, login
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.decorators import method_decorator
from .forms import LoginForm, PasswordResetRequestForm, RegisterRequestForm, SetPasswordForm
from .utils import strings


class UsersViews():
    '''
    Top class so all the users views can have an input checker.
    '''

    def check_user_input(self, input):
        '''
        Method to check the user input.
        Default: check for an email.
        :param input: User's input
        '''
        try:
            validate_email(input)
            return True
        except ValidationError:
            return False


##
# Login/Logout Views
##
class LoginRequestView(FormView, UsersViews):
    '''
    Login view.
    Config vars:
        > template_name     :: Name of the template to be rendered
        > success_url       :: If login is successful where do we go?
        > form_class        :: The login form we should use
    '''
    template_name = "login.html"
    success_url = reverse_lazy("home")
    form_class = LoginForm

    def post(self, request, *args, **kwargs):
        logout(request)
        form = self.form_class(request.POST)
        if request.POST.get('login', None) is not None:
            if form.is_valid():
                email = form.cleaned_data['email']
                if self.check_user_input(email):
                    password = form.cleaned_data['password']
                    u = authenticate(username=email, password=password)
                    if u is not None:
                        login(request=request, user=u)
                        result = self.form_valid(form)
                        messages.add_message(request=request, level=messages.SUCCESS,
                                             message=strings.LOGIN_SUCCESS)
                        return result
                    else:
                        messages.add_message(request=request, level=messages.ERROR,
                                             message=strings.LOGIN_ERR)
                else:
                    messages.add_message(request=request, level=messages.ERROR,
                                         message=strings.LOGIN_EMAIL_ERR)
            else:
                messages.add_message(request=request, level=messages.ERROR,
                                     message=strings.LOGIN_ERR)
            result = self.form_invalid(form)
            return result


class LogoutRequestView(View):
    '''
    Logout view.
    Config vars:
        > redirect_url      :: Where do we go now?
        > login_url         :: Login url in case the user is not logged in
    '''
    http_method_names = ['get', ]
    redirect_url = reverse_lazy("login")
    login_url = reverse_lazy("login")

    def get(self, request, *arks, **kargs):
        logout(request=request)
        return HttpResponseRedirect(self.redirect_url)

    @method_decorator(login_required(login_url=login_url))
    def dispatch(self, *args, **kwargs):
        return super(LogoutRequestView, self).dispatch(*args, **kwargs)


##
# Register Views
##
class RegisterRequestView(FormView, UsersViews):
    '''
    View to reset a password
    Config vars:
        > template_name     :: Template to be loades
        > success_url       :: If successful POST redirect
        > form_class        :: Userd form class
        > site_name         :: Site's name
        > subject           :: Email's subject
        > from_email        :: Sent email from (By default uses the email set on settings)
        > email_template    :: Sent email template
    '''
    template_name = 'register.html'
    form_class = RegisterRequestForm
    success_url = reverse_lazy("home")

    site_name = "Users Django App"
    subject = "Register Request"
    from_email = settings.DJANGO_USERS_FROM_EMAIL
    email_template = "register_confirm.html"

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            if self.check_user_input(email):
                response = self.save_user(form=form, email=email, request=request)
                return response
            else:
                response = self.form_invalid(form)
                messages.error(request, strings.REGISTER_MAIL_ERR)
            return response

    def save_user(self, form=None, email=None, request=None):
        '''
        Method to save the user that is requesting
        :param form: The form that the post method sends
        :param email: the user's email
        :param request
        :return Http Response
        '''
        u = get_user_model()._default_manager.filter(email=email)
        if u.exists():
            response = self.form_invalid(form)
            messages.error(request, strings.REGISTER_MAIL_REGISTERED)
        else:
            u = get_user_model()._default_manager.create_user(username=email, email=email,
                                                              password=form.cleaned_data['password'],
                                                              first_name=form.cleaned_data['first_name'],
                                                              last_name=form.cleaned_data['last_name'],
                                                              )
            u.is_active = False
            u.save()

            self.send_confirmation_mail(u=u, request=request)

            response = HttpResponseRedirect(self.success_url, strings.REGISTER_MAIL_SENT)
        return response

    def send_confirmation_mail(self, u=None, request=None):
        '''
        Method to send an activation mail to the user
        :param u: Requesting user
        :param request
        :return None
        '''
        subject = self.subject
        c = self.get_email_context(u=u, request=request)
        email = loader.render_to_string(self.email_template, c)
        send_mail(subject, email, self.from_email, [u.email, ], fail_silently=False)
        messages.add_message(request, messages.SUCCESS, strings.REGISTER_MAIL_SENT)

    def get_email_context(self, u=None, request=None):
        '''
        Method to get the context that will render the email_template
        :param user: User that requested
        :param request
        :return dict()
        '''
        return {
            'email': u.email,
            'domain': request.META['HTTP_HOST'],
            'site_name': self.site_name,
            'uid': urlsafe_base64_encode(force_bytes(u.pk)),
            'user': u,
            'token': default_token_generator.make_token(u),
            'protocol': 'http',
        }


class RegisterConfirmRequest(View):
    http_method_names = ['get']
    redirect_url = reverse_lazy("login")

    def get(self, request, uidb64=None, token=None, *arg, **kwargs):
        assert uidb64 is not None and token is not None
        user_model = get_user_model()
        try:
            uid = urlsafe_base64_decode(uidb64)
            user = user_model._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, user_model.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            messages.add_message(request, messages.SUCCESS, strings.REGISTER_CONFIRMATION)
        else:
            messages.add_message(request, messages.ERROR, strings.REGISTER_CONFIRMATION_ERR)
        return HttpResponseRedirect(self.redirect_url)


##
# Password Reset Views
##
class PasswordResetRequestView(FormView):
    '''
    View to reset a password
    Config vars:
        > template_name     :: Template to be loades
        > success_url       :: If successful POST redirect
        > form_class        :: Userd form class
        > site_name         :: Site's name
        > subject           :: Email's subject
        > from_email        :: Sent email from (By default uses the email set on settings)
        > email_template    :: Sent email template
    '''
    template_name = "password_reset.html"
    success_url = reverse_lazy("login")
    form_class = PasswordResetRequestForm

    site_name = "Users Django App"
    subject = "Register Request"
    from_email = settings.DJANGO_USERS_FROM_EMAIL
    email_template = "password_reset_email.html"

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        if form.is_valid():
            data = form.cleaned_data["email"]
        else:
            data = False
        if validate_email(data) is True:
            associated_users = get_user_model()._default_manager.filter(email=data)
            if associated_users.exists():
                for user in associated_users:
                    c = self.get_email_context(user=user, request=request)
                    subject = self.subject
                    email = loader.render_to_string(self.email_template, c)
                    send_mail(subject, email, self.from_email, [user.email], fail_silently=False)
                result = self.form_valid(form)
                messages.success(request, strings.RESET_PASSWORD_CONFIRM.format(data))
                return result
            result = self.form_invalid(form)
            messages.error(request, strings.RESET_PASSWORD_ERR_NO_EMAIL)
            return result
        messages.error(request, strings.RESET_PASSWORD_ERR_FORMAT_EMAIL)
        return self.form_invalid(form)

    def get_email_context(self, user=None, request=None):
        '''
        Method to get the context that will render the email_template
        :param user: User that requested
        :param request
        :return dict()
        '''
        return {
            'email': user.email,
            'domain': request.META['HTTP_HOST'],
            'site_name': self.site_name,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'user': user,
            'token': default_token_generator.make_token(user),
            'protocol': 'http',
        }


# Ref: http://ruddra.com/blog/2014/10/21/make-own-forgot-slash-reset-password-in-django/
class PasswordResetConfirmView(FormView):
    '''
    View to confirm the password reset
    Config vars:
        > template_name     :: Template to be loades
        > success_url       :: If successful POST redirect
        > form_class        :: Userd form class
    '''
    template_name = "password_reset_confirm.html"
    success_url = reverse_lazy("login")
    form_class = SetPasswordForm

    def post(self, request, uidb64=None, token=None, *arg, **kwargs):
        '''
        POST method.
        :param request
        :param uidb64
        :param token
        :param arg
        :param kwargs
        :return
        '''
        user_model = get_user_model()
        form = self.form_class(request.POST)
        assert uidb64 is not None and token is not None
        try:
            uid = urlsafe_base64_decode(uidb64)
            user = user_model._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, user_model.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            if form.is_valid():
                new_password = form.cleaned_data['new_password2']
                user.set_password(new_password)
                user.save()
                messages.success(request, 'Password has been reset.')
                return self.form_valid(form)
            else:
                messages.error(request, 'Password reset has not been unsuccessful.')
                return self.form_invalid(form)
        else:
            messages.error(request, 'The reset password link is no longer valid.')
            return self.form_invalid(form)
