from django.shortcuts import render,redirect
from django.http import HttpResponse
from django.contrib import messages
from datetime import datetime
from django.db.models import Q
##################
from django.contrib.auth.models import User
##########################################################################
##login and logout module
from django.contrib.auth import authenticate, login,logout
from django.contrib.auth.decorators import login_required
from django.conf import settings
#########################################################################
######################################################################
##All Model
from .models import Profile,Employee
###################################################################
from django.utils.encoding import force_bytes,force_str
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import BadHeaderError, send_mail
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator, default_token_generator
from passlib.hash import django_pbkdf2_sha256 as handler
from django.contrib.auth import update_session_auth_hash


#################################################################
from django.http import FileResponse, Http404
import json
import pprint
#################################################################

def user_login(request):
    if (request.method == 'POST'):
        username = request.POST.get('username') #Get email value from form
        password = request.POST.get('password') #Get password value from form
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            #type_obj = user_type.objects.get(user=user)
            if user.is_authenticated:
                return redirect('dashboard') 
                #return HttpResponse('login successfully')
        else:
            # Invalid email or password. Handle as you wish
            return redirect('login')
    return render(request, 'login.html')











##############################################################################
# def delete_user(request,id):
#     user= User.objects.get(id = id)
#     user.delete()
#     messages.success(request,'Record Are Successfully Deleted !')
#     return redirect('view_user')



###############################################################################
@login_required
def dashboard(request):
    # city_count=City.objects.all().count()
    # provider_count=Provider.objects.all().count()
    # datamodel_count=DataModelDomain.objects.all().count()
    # subdatamodel_count=DataModelDomainList.objects.all().count()
    # context = {
    #     'city_count':city_count,
    #     'provider_count':provider_count,
    #     'datamodel_count':datamodel_count,
    #     'subdatamodel_count':subdatamodel_count
    # }
    return render(request,'dashboard.html')

# def error_404(request, exception):
#         data = {}
#         return render(request,'certman/404.html', data)

# def error_500(request,  exception):
#         data = {}
#         return render(request,'certman/500.html', data)

def doLogout(request):
    logout(request)
    return redirect('login')
###############################################################################
@login_required
def profile(request):
    user = User.objects.get(id = request.user.id)
    profile=Profile.objects.get(user=user)
    context = {
        "user":user,
        "profile":profile
        }
    return render(request,'profile.html',context)
#################################################################################################
#login profile update first module
#################################################################################################
@login_required
def profile_update(request):
    user = User.objects.get(id = request.user.id)
    profile=Profile.objects.get(user=user)
    e=str(user.profile.date_of_birth)
    context = {
            "user":user,
            "profile":profile,
            "e":e
        }
    if request.method == "POST":
        upload = request.FILES.get('profile_pic')
        first_name = request.POST.get('name')
        country = request.POST.get('country')
        state=request.POST.get('state')
        zip_code=request.POST.get('zip_code')
        state=request.POST.get('state')
        city=request.POST.get('city')
        address=request.POST.get('address')
        login = request.POST.get('email')
        gender=request.POST.get('gender')
        mob_number=request.POST.get('mob_number')
        date_of_birth=request.POST.get('date_of_birth')
        date_time_obj = datetime.strptime(date_of_birth, '%Y-%m-%d').date()
        e=str(date_time_obj)
        password1 = request.POST.get('password1')
        password_confirm = request.POST.get('password2')
        user.name=first_name
        user.email=login
        user.profile.country=country
        user.profile.zip_code=zip_code
        user.profile.state=state
        user.profile.city=city
        user.profile.address=address
        user.profile.gender=gender
        user.profile.mob_number=mob_number
        user.profile.date_of_birth=date_time_obj
        if upload !=None and upload != "":
            user.profile.photo = upload
        if password1 !=None and password1 != "":
            user.set_password(password1)
            update_session_auth_hash(request, user)
            user.save()
            user.profile.save()
        else:
            user.save()
        if user.profile.profile_complete_status=="No":
            user.profile.profile_complete_status="yes"
            user.profile.save()
            return redirect('profile')
        #user.profile.profile_complete_status="yes"
        user.profile.save()
        context = {
        "user":user,
        "profile":profile,
        "e":e
            }
        return redirect('profile')
    else:
        return render(request,'edit_profile.html',context)
##############################################################################################
def confirm_password(request, uidb64=None, token=None):
    assert uidb64 is not None and token is not None  # checked by URLconf
    try:
        uid=force_bytes(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except:
        user = None
    if user is not None:
        if request.method == 'POST':
            if default_token_generator.check_token(user, token):
                password1 = request.POST.get('password')
                password2 = request.POST.get('password1')
                if password1 == password2 and len(password1) !=0:
                    user.set_password(password1)
                    user.save()
                    print("password save")
                    messages.success(request,'Password Changed! Login to Continue')
                    return redirect('login')
                else:
                    messages.success(request,'Both Passwords Must Match. Please try again!')
                    return redirect('password_reset_confirm',uidb64=uidb64, token=token)
            else:
                print("hello2")
                messages.success(request,"The reset password link is no longer valid. Try again!")
                return redirect('password_reset')
        elif not default_token_generator.check_token(user, token):
            messages.success(request,"The reset password link is no longer valid. Try again!")
            return redirect('password_reset')
        else:
            return render(request,'confirm_password_reset.html')
    else:
        messages.success(request,"The reset password link is no longer valid. Try again!")
        return redirect('password_reset')



@login_required
def change_password(request):
    user = User.objects.get(id = request.user.id)
    current_password = request.user.password
    print(current_password)
    if request.method == "POST":
        a=request.POST.get('last_password')
        if handler.verify(a, current_password): #user's current password
            password = request.POST.get('password')
            password1 = request.POST.get('password1')
            if password==password1:
                h = handler.hash(password)
                print(h)
                user.set_password(password)
                update_session_auth_hash(request, user)
                print('user created')
                messages.success(request,'success')
                user.save()
                return redirect('profile')
        else:
            messages.error(request,'Wrong Password')
            print("wrong password")
            return redirect('profile')
    else:
        #return render(request,'edit_profile.html',context)
        return redirect('profile')

# ###############################################################################
def password_reset(request):
    if request.method == "POST":
        domain=request.META['HTTP_HOST']
        #request.headers['User-Agent']
        #domain = HttpRequest.headers['Host']
        email = request.POST.get('email')
        associated_users = User.objects.filter(Q(email=email))
        if associated_users.exists():
            for user in associated_users:
                subject = "Password Reset Requested"
                #token_generator=default_token_generator
                #print("ytytytyty",token_generator)
                filename="templates/password_reset_email.txt" 
                email_template_name = os.path.join(BASE_DIR,filename) 
                c = {
                        "email": user.email,
                        'domain': domain,
                        'site_name': 'Interface',
                        #'token_generator': token_generator,
                        #'token_generator': default_token_generator,
                        "uid": force_str(urlsafe_base64_encode(force_bytes(user.pk))),
                        "user": user,
                        'token': default_token_generator.make_token(user),
                        #'token':default_token_generator,
                        'protocol': 'http',
                        #'use_https': request.is_secure(),
                        

                    }
                email = render_to_string(email_template_name, c)
                try:
                    send_mail(subject, email, settings.EMAIL_HOST_USER, [user.email], fail_silently=False)
                except BadHeaderError:
                    return HttpResponse('Invalid header found.')
                return redirect("password_reset")
                #return HttpResponseRedirect(post_reset_redirect)
    return render(request,"forget_password.html")


# ###########################################################################
def View_User(request,id=None):
    user1=User.objects.exclude(id=request.user.id)
    profile=Profile.objects.filter(user=user1)
    context = {
        'user1':user1,
        'profile':profile
    }
    if (request.method == 'POST'):
        print("id",id)
        print(request.POST.get('user_approval'))
        user2= User.objects.get(id = id)
        print(user2)
        profile=Profile.objects.get(user = user2)
        user2.profile.approval=request.POST.get('user_approval')
        user2.profile.save()
        return render(request,'user.html',context)
    else:
        return render(request,'user.html',context)

def delete_user(request,id):
    user= User.objects.get(id = id)
    user.delete()
    messages.success(request,'Record Are Successfully Deleted !')
    return redirect('view_user')

##############################################################################
####################################################################


############################################################################

def signup(request):
    if request.method == 'POST':
        username = request.POST.get('username') #Get email value from form
        email = request.POST.get('email') #Get email value from form
        password = request.POST.get('password') #Get password value from form
        password1 = request.POST.get('password1') #Get password value from form
        if password==password1:
            if User.objects.filter(email=email).exists():
                print("1.hello")
                messages.info(request,'Email Taken')
                return redirect('signup')
            else:
                h = handler.hash(password)
                user = User.objects.create(username=username,email=email,password=h)
                return redirect('login')     
    else:
        return render(request,'signup.html')




###Error Page

# def error_404(request, exception):
#         data = {}
#         return render(request,'certman/404.html', data)

# def error_500(request,  exception):
#         data = {}
#         return render(request,'certman/500.html', data)


###########################################################################
##crud operation


def employee_form(request):
    employee=Employee.objects.all()
    context = {
        'employee':employee,
    }
    if (request.method == 'POST'):
        employee=request.POST.get('employee_name').capitalize()
        if Employee.objects.filter(name=employee).exists():
            messages.info(request,'Already Addes employee')
            return render(request,'employee_form.html',context)
        else:
            Employee.objects.create(name=employee)
            messages.success(request, 'Employee added')
            return render(request,'employee_form.html',context)
    else:
        return render(request,'employee_form.html',context)
def delete_city(request,id):
    employee= Employee.objects.get(id =id)
    employee.delete()