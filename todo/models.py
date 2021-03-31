from django.db import models
from django.contrib.auth.models import User

class Todo(models.Model):

    title = models.CharField(max_length=100)
    memo = models.TextField(blank=True)
    created_time = models.DateTimeField(auto_now_add=True)
    completed_time = models.DateTimeField(null=True,blank=True)
    important = models.BooleanField(default=False)
    user = models.ForeignKey(User,on_delete=models.CASCADE) 

    def __str__(self):

        return self.title
    
class LoggedInUser(models.Model):
    user = models.OneToOneField(User,related_name='logged_in_user',on_delete=models.CASCADE)
    # Session keys are 32 characters long
    session_key = models.CharField(max_length=32, null=True, blank=True)

    def __str__(self):
        return self.user.username    