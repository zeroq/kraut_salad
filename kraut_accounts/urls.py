from django.conf.urls import url
from kraut_accounts import views

urlpatterns = [
    url(r'^logout/$', views.accounts_logout, name='logout'),
    url(r'^login/$', views.accounts_login, name='login'),
    url(r'^changepw/$', views.accounts_change_password, name='changepw'),
]
