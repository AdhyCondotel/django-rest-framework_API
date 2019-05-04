from rest_framework_jwt.views import ObtainJSONWebToken
from latihanDjango.utils.paginations import CustomResultsSetPagination
from rest_framework import viewsets
from rest_framework import generics
from rest_framework import status, exceptions
from rest_framework.response import Response
from myapi.models import *
from myapi.serializers import *
from rest_framework.permissions import (
    AllowAny,
    IsAuthenticated,
    IsAdminUser,
    IsAuthenticatedOrReadOnly,
    )

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



class CustomObtainJSONWebToken(ObtainJSONWebToken):
    serializer_class = CustomJWTSerializer


class TenantView(viewsets.ModelViewSet):
    queryset = Tenant.objects.all()
    serializer_class = TanantSerializer
    pagination_class = CustomResultsSetPagination

class AddressView(viewsets.ModelViewSet):
    queryset = Address.objects.all()
    serializer_class = AddressSerializer
    permission_classes = (IsAuthenticated,)
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