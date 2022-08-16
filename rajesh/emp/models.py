from django.db import models
from django.contrib.auth.models import User
from django.dispatch import receiver
from django.db.models.signals import post_save
from django.core.validators import RegexValidator


from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    USER_TYPE=(('manager', 'Manager'),('employee', 'Employee'),('operation','Operation'),)
    role     =models.CharField(max_length=10,choices=USER_TYPE,)




# class Profile(models.Model):
#     Gender = (
#     ('Male','Male'),
#     ('Female', 'Female'),
#     )
#     user = models.OneToOneField(User, on_delete=models.CASCADE)
#     date_of_birth = models.DateField(blank=True, null=True)
#     photo = models.ImageField(upload_to='pic', blank=True,default='default.jpg')
#     phone_regex = RegexValidator(regex=r'^\+?1?\d{9,15}$', message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.")
#     mob_number = models.CharField(validators=[phone_regex], max_length=10, blank=True) # Validators should be a list
#     gender = models.CharField(max_length=6, choices=Gender, default='Male')
#     address=models.CharField(max_length=50)
#     city=models.CharField(max_length=20)
#     state=models.CharField(max_length=50)
#     zip_code=models.CharField(max_length=6)
#     country=models.CharField(max_length=50 ,default='India')
#     def __str__(self):
#         return 'Profile for user {}'.format(self.user.email)


@receiver(post_save, sender=User)
def update_profile_signal(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)
    instance.profile.save()

class Employee(models.Model):
	name = 	models.CharField(max_length=250)

	def __str__(self):
		return self.name
