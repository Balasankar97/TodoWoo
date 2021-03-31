"""Todowoo URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path,include
from todo import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('admin/', admin.site.urls),
    
    
    #Authentication
    path('signup/',views.signupuser,name='signupuser'),
    path('logout',views.logoutuser,name='logoutuser'),
    path('login',views.loginuser,name='loginuser'),
    
    #Home page
    path('',views.home,name='home'),


    #Todos
    path('current',views.current,name='current'),
    path('create',views.createtodo,name='createtodo'),
    path('completed',views.completedtodos,name='completedtodos'),
    path('todo/<int:todo_pk>',views.todoview,name='todoview'),
    path('todo/<int:todo_pk>/complete',views.todocomplete,name='todocomplete'),
    path('todo/<int:todo_pk>/delete',views.tododelete,name='tododelete'),
   #path('setsession',views.set_session,name='set_session'),
   #path('getsession',views.get_session,name='get_session'),

    #reset password

    path("password_reset", views.password_reset, name="password_reset"),

    path('reset_password_sent/', 
        auth_views.PasswordResetDoneView.as_view(template_name="todo/password_reset_sent.html"), 
        name="password_reset_done"),

    path('reset/<uidb64>/<token>/',
     auth_views.PasswordResetConfirmView.as_view(template_name="todo/password_reset_form.html"), 
     name="password_reset_confirm"),

    path('reset_password_complete/', 
        auth_views.PasswordResetCompleteView.as_view(template_name="todo/password_reset_done.html"), 
        name="password_reset_complete"),
]

'''
1 - Submit email form                         //PasswordResetView.as_view()
2 - Email sent success message                //PasswordResetDoneView.as_view()
3 - Link to password Rest form in email       //PasswordResetConfirmView.as_view()
4 - Password successfully changed message     //PasswordResetCompleteView.as_view()
'''
