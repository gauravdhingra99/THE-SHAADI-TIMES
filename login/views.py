from django.contrib.auth import login, authenticate,logout
from django.shortcuts import render, redirect
from django.shortcuts import render,HttpResponse
from .models import Profile
import random
from django.http import HttpResponse
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from .tokens import account_activation_token
from django.contrib.auth.models import User
from django.core.mail import EmailMessage


def home(request):
 return render(request,"login/index.html",{})



def signup(request):
    print(request.POST)
    if request.method == 'POST':
        username = request.POST.get('username')
        firstname = request.POST.get('firstname')
        lastname = request.POST.get('lastname')
        email=request.POST.get('email')
        password1=request.POST.get('pass1')
        password2=request.POST.get('pass2')
        print(firstname)

        if firstname and lastname and email and password1==password2:
            print("andar")
            try:
                user = User.objects.create_user(username=username,password=password1,first_name=firstname,last_name=lastname,email=email)
                #print("dnmf",user)
                user.is_active = False
                user.save()
                #print("mera",user)
                current_site = get_current_site(request)
                #print(current_site)
                mail_subject = 'Activate your blog account.'
                message = render_to_string('acc_active_email.html', {'user': user, 'domain': current_site.domain,
                    'uid': str(urlsafe_base64_encode(force_bytes(user.pk))), 'token': account_activation_token.make_token(user), })
                #print(message)
                email = EmailMessage(mail_subject, message, to=[email])
                #print(email)
                email.send()
                #print("bejdeya")
                return  render(request,"login/login.html",{"message":"Email-Verification code has been sent to your mail. Please veriy and then Login to continue."})
            except:
                return  render(request,"login/signup.html",{"message":"Username with this name already exists."})
        else:
            return  render(request,"login/signup.html",{"message":"Password should be same."})

    return  render(request,"login/signup.html")


def login(request):
    if not request.user.is_anonymous:
        logout(request)
        print("user logged out")
    else:
        user=request.POST.get("username")
        password=request.POST.get("password")
        print(request.POST)
        if not User.objects.filter(username=user).exists():
            return  render(request,"login/login.html",{"message":"Sorry User with this username does not exists."})
        user_obj=authenticate(username=user,password=password)
        print(user_obj)
        if user_obj is None:
            return  render(request,"login/login.html",{"message":"Wrong Password Click <a href='/home/'>Here</a> to try again."})
        if not user_obj.is_staff:
            return render(request, "login/login.html",{"message": "Please Confirm  your email to login."})
        elif user_obj.is_staff:
            print('aaaaaaaaaaaaaa')
            print(request)
            print(user_obj)
            login(request,user_obj)
            return redirect("/welcome/")
        elif user_obj.is_staff==False :
            return HttpResponse("Sorry you can't participate in this contest.")
        else:
            return HttpResponse("Sorry you can't participate in this contest.")
    return  render(request,"login/login.html")



def logoutuser(request):
    logout(request)
    return redirect("/home/")


def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.is_staff=True
        user.save()
        # return redirect('home')
        return  render(request,"login/login.html",{"message":"Thank you for your email confirmation. Now you can login your account. "})
    else:
        return render(request, "login/login.html", {'message':'Activation link is invalid!'})




