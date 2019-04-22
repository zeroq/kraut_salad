from django.conf.urls import url
from rest_framework.urlpatterns import format_suffix_patterns
from kraut_search import views

urlpatterns = [
    # indicators
    url(r'^$', views.base_search),
]

urlpatterns = format_suffix_patterns(urlpatterns)
