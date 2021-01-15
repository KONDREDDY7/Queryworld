from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.core.validators import RegexValidator
from django.db import models
from django.contrib.auth.models import PermissionsMixin

# Create your models here.


class UserManager(BaseUserManager):

    def create_user(self, email, name, password=None, is_active=True, is_staff=False, is_admin=False):
        if not email:
            raise ValueError('User must have the email')
        if not password:
            raise ValueError('User must have the password ')
        user_obj = self.model(
            email=email,
            name=name,
        )
        user_obj.set_password(password)
        user_obj.admin = is_admin
        user_obj.active = is_active
        user_obj.staff = is_staff
        user_obj.save(using=self._db)
        return user_obj

    def create_staffuser(self, email, password=None):
        user = self.create_user(
            email=email,
            password=password,
            is_staff=True,
        )
        return user

    def create_superuser(self, email, name, password=None):
        user = self.create_user(
            email,
            name,
            is_staff=True,
            password=password,
            is_admin=True,
        )
        return user


class User(AbstractBaseUser, PermissionsMixin):
    name = models.CharField(max_length=20)
    email = models.EmailField(max_length=50, unique=True)
    first_login = models.BooleanField(default=False)
    active = models.BooleanField(default=True)
    staff = models.BooleanField(default=False)
    admin = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']

    objects = UserManager()

    def __str__(self):
        return self.name

    def get_full_name(self):
        if self.name:
            return self.name
        return self.email

    def get_short_name(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        return self.staff

    @property
    def is_admin(self):
        return self.admin


# class Question(models.Model):
#     user = models.ForeignKey(User, on_delete=models.CASCADE)
#     question_text = models.CharField(max_length=100)


class UserMail(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sender')
    reciever = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='reciever', null=True)
    subject = models.CharField(max_length=100, null=True, blank=True)
    message = models.CharField(max_length=500)
    attachment = models.FileField(upload_to='media/', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.sender.name)+str(self.reciever.name)
