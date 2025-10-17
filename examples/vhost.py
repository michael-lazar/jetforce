"""
A server that implements virtual hosting for subdomains.

This is a basic example of you how can run multiple apps from the same server.
You can use different static directories for different domains, or even combine
static applications with your own custom JetforceApplication classes.

> jetforce-client gemini://app-a.example.com --host localhost
> jetforce-client gemini://app-b.example.com --host localhost

This is how gemini://astrobotany.mozz.us is served alongside gemini://mozz.us:

```
app = jetforce.CompositeApplication(
    {
        "astrobotany.mozz.us": astrobotany_application,
        None: StaticDirectoryApplication(),
    }
)
```
"""

from jetforce import GeminiServer, StaticDirectoryApplication
from jetforce.app.composite import CompositeApplication

app_a = StaticDirectoryApplication(root_directory="/var/custom_directory_a/")
app_b = StaticDirectoryApplication(root_directory="/var/custom_directory_b/")
app_default = StaticDirectoryApplication(root_directory="/var/gemini/")

app = CompositeApplication(
    {
        "app-a.example.com": app_a,
        "app-b.example.com": app_b,
        # Use a default static file server for all other domains
        None: app_default,
    }
)


if __name__ == "__main__":
    server = GeminiServer(app)
    server.run()
