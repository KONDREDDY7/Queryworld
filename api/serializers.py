from django.contrib.auth import authenticate
from rest_framework import serializers
from .models import User, UserMail
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password


class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )

    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('name', 'password', 'confirm_password', 'email',)

    def validate_password(self, value):
        import re
        if value.isalnum():
            raise serializers.ValidationError('password must have atleast one special character.')
        if len(value) < 8:
            raise serializers.ValidationError('password is too small, it should be atleast 12 characters long')
        if len(re.findall(r'\d', value)) < 2 and len(re.findall(r'\W', value)) < 2 and len(
                re.findall(r'\w', value)) < 8:
            raise serializers.ValidationError(
                """
                didn't match the following conditons which contains
                1) minimum 8 letters , 
                2) 2 numbers and 
                3) 2 special chars
                """
            )
        return value

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            name=validated_data['name'],
            email=validated_data['email'],
        )

        user.set_password(validated_data['password'])
        user.save()

        return user


class UserLoginSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=255)
    password = serializers.CharField(max_length=128, write_only=True)
    token = serializers.CharField(max_length=500, read_only=True)


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('name', 'email',)


class MailSerializer(serializers.ModelSerializer):
    sender = UserSerializer()
    reciever = UserSerializer()
    created_at = serializers.CharField(max_length=500, read_only=True)
    modified_at = serializers.CharField(max_length=500, read_only=True)

    class Meta:
        model = UserMail
        fields = ('sender', 'reciever', 'subject', 'message', 'attachment', 'created_at', 'modified_at',)
