from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

from django.contrib.auth.models import AbstractUser

class CustomUser(AbstractUser):
	phone = models.CharField(blank=True, max_length=15)
	role = models.CharField(default='user', max_length=50, blank=True)
	
	def __str__(self):
		return self.email

class Tenant(models.Model):
	user = models.OneToOneField(CustomUser, related_name='tenant_id', on_delete=models.CASCADE, null=True, blank=True)
	name= models.CharField(max_length=100)
	delivery = models.BooleanField(default='False')
	status = models.BooleanField(default='False')
	address = models.CharField(max_length=220)
	address_Latitude = models.CharField(max_length=50)
	address_Longitude = models.CharField(max_length=50)
	photo = models.TextField()
	created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
	updated_at = models.DateTimeField(auto_now=True, null=True, blank=True)
	
	def __str__(self):
		return self.name


class Address(models.Model):
	as_address = models.CharField(max_length=50)
	name = models.CharField(max_length=200)
	address = models.CharField(max_length=225)
	phone = models.CharField(max_length=15)
	province = models.CharField(max_length=100)
	city = models.CharField(max_length=100) 
	keluarahan = models.CharField(max_length=100)
	status = models.BooleanField()
	created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
	updated_at = models.DateTimeField(auto_now=True, null=True, blank=True)

	def __str__(self):
		return self.as_alamat
