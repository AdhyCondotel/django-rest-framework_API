from django.urls import include, path
from rest_framework import routers
from rest_framework_jwt.views import (obtain_jwt_token, refresh_jwt_token,
                                      verify_jwt_token)

from .views import (
    AddressView, 
    TenantView, 
    UserCreate, 
    CustomJWTSerializer
)

from rest_framework_jwt.views import ObtainJSONWebToken



router = routers.DefaultRouter()
router.register(r'address', AddressView),
router.register(r'tenant', TenantView),

urlpatterns = [
    path('', include(router.urls)),
    #path(r'login' , obtain_jwt_token),
    path(r'login', ObtainJSONWebToken.as_view(serializer_class=CustomJWTSerializer)),
    path("register/", UserCreate.as_view(), name="register"),
    path(r'token-refresh', refresh_jwt_token),
    path(r'token-verify', verify_jwt_token),


    

]
