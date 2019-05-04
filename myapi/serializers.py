from rest_framework.authtoken.models import Token
from rest_framework_jwt.settings import api_settings
from django.utils.translation import ugettext as _
from rest_framework import status, exceptions
from rest_framework_jwt.serializers import JSONWebTokenSerializer
from rest_framework_jwt.compat import PasswordField
from django.db.models import Q
from django.contrib.auth import authenticate, get_user_model
from rest_framework.permissions import IsAuthenticated

from rest_framework import serializers
from .models import (
    CustomUser,
    Address,
    Tenant,
)


User = get_user_model()
jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
jwt_decode_handler = api_settings.JWT_DECODE_HANDLER
jwt_get_username_from_payload = api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER


class UserSerializer(serializers.ModelSerializer):
    tenant_id = serializers.PrimaryKeyRelatedField(read_only=True)
    class Meta:
        model = CustomUser
        fields = ('first_name', 'username', 'email', 'password', 'phone', 'role', 'tenant_id')
        extra_kwargs = {
            'password': {'write_only': True},
            'phone': {'write_only': True},
        }

    def create(self, validated_data):
        user = CustomUser(
            first_name=validated_data['first_name'],
            username=validated_data['username'],
            email=validated_data['email'],
            phone=validated_data['phone'],
            role=validated_data['role'],
        )
        user.set_password(validated_data['password'])
        user.save()
        Token.objects.create(user=user)
        return user


class CustomJWTException(exceptions.APIException):
    status_code = 401
    default_detail = 'Bad Request.'
    # default_code = 'service_unavailable'


class CustomJWTSerializer(JSONWebTokenSerializer):
    username_field = 'username_or_email'
    username_or_email = serializers.CharField(required=False)
    password = PasswordField(write_only=True, required=False)

    def validate(self, attrs):
        password = attrs.get("password")
        user_obj = User.objects.filter(
            Q(username=attrs.get('username_or_email')) | Q(email=attrs.get('username_or_email'))).first()
        msg = None
        if user_obj is not None:
            credentials = {
                'username': user_obj.username,
                'password': password
            }
            if all(credentials.values()):
                user = authenticate(**credentials)
                if user:
                    if not user.is_active:
                        msg = _('User account is disabled.')

                    payload = jwt_payload_handler(user)

                    return {
                        'token': jwt_encode_handler(payload),
                        'user': user
                    }
                else:
                    msg = _('Unable to log in with provided credentialss.')

            else:
                msg = _('Must include "{username_field}" and "password".')
                msg = msg.format(username_field=self.username_field)

        else:
            msg = _('Account with this email/username does not exists')

        if msg:
            raise CustomJWTException(msg)

        return attrs
        
class TanantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tenant
        fields = '__all__'
        
class AddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = '__all__'
