from django.shortcuts import render,redirect,get_object_or_404,HttpResponse
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.contrib.auth import login, logout, authenticate
from .forms import TodoForm, CreateUserForm, PasswordResettingForm
from .models import Todo
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.db.models.query_utils import Q
from django.http import HttpResponse
from django.core.mail import send_mail, BadHeaderError, EmailMultiAlternatives
from django.contrib import sessions,messages
import re

#Home page
def home(request):

    return render(request,'todo/home.html')

#Authentication Part


def signupuser(request):

    email_pattern = r'[\w-]{1,20}@\w{1,20}\.(com$|in$)'
    pwd_pattern = "^.*(?=.{8,})(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$"

    if request.method == 'GET':
        return render(request,'todo/signupuser.html',{'form': CreateUserForm()})

    else:
        if re.match(email_pattern, request.POST['email']):
            if len(request.POST['password1'])>6 and re.match(pwd_pattern, request.POST['password1']) and len(request.POST['password1'])<20:
            #comparing whether the entered and re-entered passwords are Username
                print("HI")
                if request.POST['password1'] ==  request.POST['password2']:
                    if request.POST['username'].lower() not in request.POST['password1'].lower():
                        try:
                            if User.objects.filter(email = request.POST['email']).exists():
                                return render(request,'todo/signupuser.html',{'form': CreateUserForm(), 'error':'email already exists'})
                            else:
                                user=User.objects.create_user(request.POST['username'],password=request.POST['password1'],email=request.POST['email'])
                                user.save()
                                login(request,user)
                                return redirect('current')
                            #if there is an already existing user
                        except IntegrityError:
                            #context = {'error':"Username is taken. Please try again"}
                            return render(request,'todo/signupuser.html',{'form': CreateUserForm(), 'error':'user already exists. Please enter a new username'})
                    else:
                         return render(request,'todo/signupuser.html',{'form': CreateUserForm(), 'error':'password should not contain username characters'})
                else:
                    #tell user that password didn't match
                    return render(request,'todo/signupuser.html',{'form': CreateUserForm(), 'error':'Password doesn\'t match. Please reconfirm it.'})

            else:
                return render(request,'todo/signupuser.html',{'form': CreateUserForm(), 'error':'Enter valid password'})
        else:
            return render(request,'todo/signupuser.html',{'form': CreateUserForm(), 'error':'Enter a valid mail_id '})

def loginuser(request):

    if request.method == 'GET':
        return render(request,'todo/loginuser.html',{'form': AuthenticationForm()})
    else:
        if(request.POST['username'] == '' or request.POST['password'] == ''):
            
            return render(request,'todo/loginuser.html',{'form': AuthenticationForm(), 'error':'All the fields are mandatory. Please enter all the fields.'})
        
        user=authenticate(request,username=request.POST['username'],password=request.POST['password'])
        if user is None:

            return render(request,'todo/loginuser.html',{'form': AuthenticationForm(), 'error':'Username or password is invalid. Please try again.'})

        else:
            login(request,user)
            return redirect('current')

@login_required
def logoutuser(request):

    if request.method == "POST":
        logout(request)
        return redirect('home')


#creation,view,updation and deletion of todos part
@login_required
def createtodo(request):
    if request.method == 'GET':
        return render(request,'todo/createtodo.html',{'form': TodoForm()})
    else:
        try:
            form = TodoForm(request.POST)
            newtodo = form.save(commit=False)
            newtodo.user = request.user
            newtodo.save()
            return redirect('current')
        except ValueError:
            return render(request,'todo/createtodo.html',{'form': TodoForm(), 'error':'Invalid data. renter again.'})

#@login_required
def current(request):
    if request.user.is_authenticated:
        todos = Todo.objects.filter(completed_time__isnull=True,user=request.user)
        return render(request,'todo/current.html',{'todos': todos})
    
    else:
        messages.success(request,'Your session has expired.')
        return redirect('loginuser')
    #if not request.user.is_authenticated:
    #    return redirect('loginuser')
    #else:
    #    todos = Todo.objects.filter(completed_time__isnull=True,user=request.user)
    #    request.session['name'] = str(request.user)
    #    print(request.session.get('name'))
    #    if request.session.get('name'):
    #        print('hi')
    #        return render(request,'todo/current.html',{'todos': todos})
    #    elif request.session.has_key():
    #        print('beinchod')
    #        messages.success(request,'Your session has expired.')
    #        return redirect('loginuser') 
         
            
            
@login_required
def todoview(request,todo_pk):
    todo = get_object_or_404(Todo,pk=todo_pk,user=request.user)
    if request.method == 'GET':
        form=TodoForm(instance=todo)
        return render(request,'todo/todoview.html',{'todo':todo,'form':form})

    else:
        try:
            form=TodoForm(request.POST,instance=todo)
            form.save()
            return redirect('current')
        except ValueError:
            return render(request,'todo/todoview.html',{'todo':todo,'form':form,'error':'Invalid data. renter again.'})

@login_required
def todocomplete(request,todo_pk):
    todo = get_object_or_404(Todo,pk=todo_pk,user=request.user)
    if request.method == 'POST':
        todo.completed_time = timezone.now()
        todo.save()
        return redirect('current')

@login_required
def tododelete(request,todo_pk):
    todo = get_object_or_404(Todo,pk=todo_pk,user=request.user)
    if request.method == 'POST':
        todo.delete()
        return redirect('current')


def completedtodos(request):
    todos = Todo.objects.filter(completed_time__isnull=False,user=request.user).order_by('-completed_time')
    return render(request,'todo/completedtodos.html',{'todos': todos})

def password_reset(request):
    if request.method == 'POST':
        password_reset_form = PasswordResettingForm(request.POST)
        #email_user=PasswordResettingForm(request.POST['email'])
        #print(password_reset_form)
        print(type(password_reset_form))
        if password_reset_form.is_valid:
            associated_users = User.objects.filter(email=request.POST.get('email'))
            #print(associated_users)
            #print(type(associated_users))
            if len(associated_users) == 0:
                return render(request,'todo/password_reset.html',{'password_reset_form':PasswordResettingForm(),'error':'e-mail is not registered. Please try with registered mail.'})
            
            else:  
                
                for user in associated_users:
                    
                    if User.objects.filter(email = request.POST['email']).exists(): 
                        #print(user.id)
                        #print(user)
                        #print(user.email)
                        subject = 'Password Reset request'
                        email_template = "todo/e_mail.txt"
                        c= {"email":user.id, "domain":'127.0.0.1:8000', 'site_name':'website',"uid":urlsafe_base64_encode(force_bytes(user.id)),
                            "user":user,"token":default_token_generator.make_token(user),"protocol":'http'}
                        email = render_to_string(email_template,c)
                        try:
                            send_mail(subject,email,'pbalasankar97@gmail.com',[user.email])
                        except BadHeaderError:
                            return HttpResponse("invalid header found.")
                        
                        return redirect("password_reset_done")    
                    
                    
                    
              
    password_reset_form = PasswordResettingForm()         
    return render(request, "todo/password_reset.html", {"password_reset_form":password_reset_form})

#@login_required
#def set_session(request):
#    
#    request.session['request.user'] = request.user
#    return render(request,'todo/setsession.html')
#
#@login_required
#def get_session(request):
#   
#    if request.user in request.session:    
#        name = request.session.get('request.user')
#        return render(request,'todo/getsession.html',{'name':name})

#        return HttpResponse('your session has been expired')
       
        
    








            
    
    
