from django.forms import ModelForm
from django.contrib.auth.forms import UserCreationForm,PasswordResetForm
from django import forms
from django.contrib.auth.models import User
from  .models import Todo
from django.db import models
from django.core.exceptions import ValidationError
import re


class TodoForm(ModelForm):
    class Meta:
        model = Todo
        fields=['title','memo','important']

class CreateUserForm(UserCreationForm):
    email = forms.EmailField(required=True)
    class Meta:
        model = User
        fields = ['username','email','password1','password2',]
        
class PasswordResettingForm(PasswordResetForm):
    email = forms.EmailField(required=True)        
    class Meta:
        fields = ['email']
    def clean_email(self):
        email_pattern = r'[\w-]{1,20}@\w{1,20}\.(com$|in$)'

        user_email = self.cleaned_data.get('user_email')
        if re.match(email_pattern,user_email):
            return user_email
        else:
            raise ValidationError("Invalid user email")
        
        
            
        
