"""
This example demonstrates displaying search results using pagination.

Named capture groups (?P<name>...) will be passed along as additional keyword
arguments to the wrapped function. You can apply two routes to the same view in
order to make the page number optional in the URL.

Try to think outside of the box when you design your UX. Will users need to
navigate forward/backward through the results, or only forward? Should the
number or results returned per-page be controllable?

> jetforce-client https://localhost/docs/ssl/p/1
"""
import math
import ssl

from jetforce import GeminiServer, JetforceApplication, Response, Status

modules = {"ssl": ssl.__doc__, "math": math.__doc__}
paginate_by = 10

app = JetforceApplication()


@app.route("", strict_trailing_slash=False)
def index(request):
    lines = ["View documentation for the following modules:", ""]
    for module in modules:
        lines.append(f"=>/docs/{module} {module}")
    return Response(Status.SUCCESS, "text/gemini", "\n".join(lines))


@app.route("/docs/(?P<module>[a-z]+)")
@app.route("/docs/(?P<module>[a-z]+)/p/(?P<page>[0-9]+)")
def docs(request, module, page=1):
    page = int(page)

    if module not in modules:
        return Response(Status.NOT_FOUND, f"Invalid module {module}")

    help_text_lines = modules[module].splitlines()

    page_count = math.ceil(len(help_text_lines) / paginate_by)
    page_count = max(page_count, 1)
    if page > page_count:
        return Response(Status.NOT_FOUND, "Invalid page number")

    offset = (page - 1) * paginate_by
    items = help_text_lines[offset : offset + paginate_by]

    lines = [f"[{module}]", f"(page {page} of {page_count})", ""]
    lines.extend(items)
    lines.append("")
    if page < page_count:
        lines.append(f"=>/docs/{module}/p/{page+1} Next {paginate_by} lines")
    if page > 1:
        lines.append(f"=>/docs/{module} Back to the beginning")

    return Response(Status.SUCCESS, "text/gemini", "\n".join(lines))


if __name__ == "__main__":
    server = GeminiServer(app)
    server.run()
