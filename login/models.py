from django.db import models
from django.contrib.auth.models import User
# Create your models here.



class Profile(models.Model):
    user =models.OneToOneField(User,on_delete=models.CASCADE)
    email = models.EmailField(max_length=70, blank=False, unique=True)
    

    def __str__(self):
        return self.user.username
