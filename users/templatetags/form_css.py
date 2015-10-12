__author__ = 'gomes'

from django import template

register = template.Library()


@register.filter(name='add_input_attr')
def add_input_attr(field, attr):
    values = {}
    for i in attr.split(';'):
        values[i.split(':')[0]] = i.split(':')[1]
    return field.as_widget(attrs=values)
