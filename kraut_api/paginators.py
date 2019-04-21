# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from rest_framework import pagination, status
from django.http import JsonResponse
from django.core.paginator import Paginator as DjangoPaginator
from django.db import connection
from django.utils.functional import cached_property


class KrautCustomPaginator(DjangoPaginator):
    @cached_property
    def count(self):
        try:
            with connection.cursor() as cursor:
                table_name = self.object_list.model._meta.db_table
                cursor.execute("SELECT reltuples::BIGINT AS estimate FROM pg_class WHERE relname='%s';" % table_name)
                row = cursor.fetchone()
                return row[0]
        except:
            try:
                return self.object_list.count()
            except (AttributeError, TypeError):
                return len(self.object_list)

class CustomPaginator(pagination.PageNumberPagination):
    django_paginator_class = KrautCustomPaginator

    def get_page_size(self, request):
        if request.query_params:
            return int(request.query_params.get('length', 25))
        return 25

    def paginate_queryset(self, queryset, request, view=None):
        page_size = self.get_page_size(request)
        paginator = self.django_paginator_class(queryset, page_size)
        if request.query_params:
            page_number = int(int(request.query_params['start'])/int(page_size))+1
        else:
            page_number = 1
        try:
            self.page = paginator.page(page_number)
        except:
            self.page = 1
        self.request = request
        return list(self.page)

    def get_paginated_response(self, data):
        item_count = self.page.paginator.count
        return JsonResponse({
            "status": True,
            "code": status.HTTP_200_OK,
            "next": self.get_next_link(),
            "previous": self.get_previous_link(),
            "count": item_count,
            "iTotalRecords": item_count,
            "iTotalDisplayRecords": item_count,
            "results": data
        }, json_dumps_params={'indent': 2})
