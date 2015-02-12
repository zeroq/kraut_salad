
from django import template
register = template.Library()

@register.filter(name='addcss')
def addcss(field, args):
    css, place = args.split(',')
    return field.as_widget(attrs={"class":css, "placeholder": place})
