from rest_framework.authtoken.models import Token

from rest_framework import serializers
from .models import (
    CustomUser,
    Address,
    Tenant,
)

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

        
class TanantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tenant
        fields = '__all__'
        
class AddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = '__all__'
