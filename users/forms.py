__author__ = 'gomes'

from django import forms
from .utils import strings


class LoginForm(forms.Form):
    email = forms.CharField(label=strings.LBL_EMAIL, max_length=254, required=True)
    password = forms.CharField(label=strings.LBL_PASSWORD, widget=forms.PasswordInput, required=True)


class PasswordResetRequestForm(forms.Form):
    email = forms.CharField(label=strings.LBL_PASSWORD, max_length=254)


class SetPasswordForm(forms.Form):
    error_messages = {
        'password_mismatch': strings.PASSWORD_MISMATCH,
    }
    new_password1 = forms.CharField(label=strings.LBL_NEW_PASSWORD,
                                    widget=forms.PasswordInput)
    new_password2 = forms.CharField(label=strings.LBL_NEW_PASSWORD_CONFIRM,
                                    widget=forms.PasswordInput)

    def clean_new_password2(self):
        password1 = self.cleaned_data.get('new_password1')
        password2 = self.cleaned_data.get('new_password2')
        if password1 and password2:
            if password1 != password2:
                raise forms.ValidationError(
                    self.error_messages['password_mismatch'],
                    code='password_mismatch',
                )
        return password2


class RegisterRequestForm(forms.Form):
    email = forms.EmailField(label='Email', required=True)
    password = forms.CharField(label='Password', widget=forms.PasswordInput, required=True)
    first_name = forms.CharField(label='First Name', max_length=128, required=True)
    last_name = forms.CharField(label='Last Name', max_length=128, required=True)
