from django import template
register = template.Library()

@register.filter("split_at")
def split_at(value, params):
    try:
        split_value, return_position = params.split(',')
        return value.split(split_value)[int(return_position)]
    except:
        return value
