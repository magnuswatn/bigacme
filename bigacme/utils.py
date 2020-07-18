import logging
import string

import click

logger = logging.getLogger(__name__)


def validate_bigip_name(ctx, param, value):
    """
    Big-IP is kinda picky about names. Names with special characters
    will (mostly) get rejected, and some (slashes) will lead to unexpected
    results (path traversal). Best not to accept names like that.
    """
    if not value:
        return None

    allowed_characters = string.ascii_letters + string.digits + "._-"

    for char in value:
        if char not in allowed_characters:
            raise click.BadParameter("The requested object name is invalid")
    return value


def print_table(headers, values):
    """Prints an OK (ish) ascii table"""
    max_widths = [len(str(x)) for x in headers]
    for value in values:
        max_widths = [max(x, len(str(y))) for x, y in zip(max_widths, value)]

    header = [str(c).ljust(w) for w, c in zip(max_widths, headers)]
    separator = ["-" * x for x in max_widths]

    click.secho("+ {} +".format(" + ".join(list(separator))))
    click.secho("| {} |".format(" | ".join(list(header))), bold=True)
    click.secho("+ {} +".format(" + ".join(list(separator))))

    for value in values:
        cols = [str(c).ljust(w) for w, c in zip(max_widths, value)]
        click.secho("| {} |".format(" | ".join(list(cols))))

    click.secho("+ {} +".format(" + ".join(list(separator))))
