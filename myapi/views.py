from rest_framework_jwt.compat import PasswordField
from rest_framework_jwt.views import ObtainJSONWebToken
from rest_framework_jwt.settings import api_settings
from django.utils.translation import ugettext as _
from django.contrib.auth import authenticate, get_user_model
from rest_framework_jwt.serializers import JSONWebTokenSerializer
from django.db.models import Q
from rest_framework.permissions import AllowAny, IsAuthenticated
from latihanDjango.utils.paginations import CustomResultsSetPagination
from rest_framework import viewsets
from rest_framework import generics
from rest_framework import status, exceptions
from rest_framework.response import Response
from myapi.models import *
from myapi.serializers import *

class UserCreate(generics.CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = UserSerializer
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response({"detail" : "Success","status_code": status.HTTP_201_CREATED},
                status=status.HTTP_201_CREATED, headers=headers)

        return Response({"detail" : serializer.errors, "status_code": status.HTTP_400_BAD_REQUEST}, 
            status=status.HTTP_400_BAD_REQUEST)




from rest_framework_jwt.serializers import JSONWebTokenSerializer
from django.contrib.auth import authenticate, get_user_model
from django.utils.translation import ugettext as _

from rest_framework_jwt.settings import api_settings
User = get_user_model()
jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
jwt_decode_handler = api_settings.JWT_DECODE_HANDLER
jwt_get_username_from_payload = api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER



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


class CustomObtainJSONWebToken(ObtainJSONWebToken):
    serializer_class = CustomJWTSerializer

# class CustomJWTSerializer(JSONWebTokenSerializer):
    username_field = 'username_or_email'
    def validate(self, attrs):
        password = attrs.get("password")
        user_obj = User.objects.filter(email=attrs.get("username_or_email")).first() or User.objects.filter(username=attrs.get("username_or_email")).first()
        if user_obj is not None:
            credentials = {
                'username':user_obj.username,
                'password': password
            }
            if all(credentials.values()):
                user = authenticate(**credentials)
                if user:
                    if not user.is_active:
                        msg = _('User account is disabled.')
                        raise serializers.ValidationError(msg)

                    payload = jwt_payload_handler(user)

                    return {
                        'token': jwt_encode_handler(payload),
                        'user': user
                    }
                else:
                    msg = _('Unable to log in with provided credentials.')
                    raise serializers.ValidationError(msg)

            else:
                msg = _('Must include "{username_field}" and "password".')
                msg = msg.format(username_field=self.username_field)
                raise serializers.ValidationError(msg)

        else:
            res = {"code": 400, "message": "Bad Requset"}
            return Response(res)
                        # msg = _('Must include "{username_field}" and "password".')
            # msg = msg.format(username_field=self.username_field)
            # raise serializers.ValidationError(msg)

class TenantView(viewsets.ModelViewSet):
    queryset = Tenant.objects.all()
    serializer_class = TanantSerializer
    pagination_class = CustomResultsSetPagination

class AddressView(viewsets.ModelViewSet):
    queryset = Address.objects.all()
    serializer_class = AddressSerializer
    permission_classes = (AllowAny,)
    pagination_class = CustomResultsSetPagination

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response({"detail" : "Success","status_code": status.HTTP_201_CREATED},
                status=status.HTTP_201_CREATED, headers=headers)

        return Response({"detail" : "error", "status_code": status.HTTP_400_BAD_REQUEST}, 
            status=status.HTTP_400_BAD_REQUEST)


    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid(raise_exception=False):
            self.perform_update(serializer)
            headers = self.get_success_headers(serializer.data)
            if getattr(instance, '_prefetched_objects_cache', None):
                instance._prefetched_objects_cache = {}
            return Response({"detail" : "Success","status_code": status.HTTP_202_ACCEPTED},
                status=status.HTTP_202_ACCEPTED, headers=headers)

        return Response({"detail" : "error", "status_code": status.HTTP_400_BAD_REQUEST}, 
            status=status.HTTP_400_BAD_REQUEST)    


    def partial_update(self, request, pk=None):
        return Response("partial_update data")


    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"detail" : "Success","status_code": status.HTTP_204_NO_CONTENT},
            status=status.HTTP_204_NO_CONTENT)