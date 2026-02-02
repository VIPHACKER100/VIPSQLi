"""
Built-in Security Testing Plugins

This package contains enhanced security testing plugins for detecting
various web application vulnerabilities.

Available Plugins:
- GraphQLPlugin: GraphQL injection and security testing
- NoSQLPlugin: NoSQL injection detection (MongoDB, CouchDB, etc.)
"""

from .graphql import GraphQLPlugin
from .nosql import NoSQLPlugin

__all__ = ['GraphQLPlugin', 'NoSQLPlugin']
__version__ = '2.0.0'

# Plugin metadata
PLUGINS = {
    'graphql': {
        'class': GraphQLPlugin,
        'name': 'GraphQL Injection',
        'version': '2.0.0',
        'description': 'Comprehensive GraphQL security vulnerability detection'
    },
    'nosql': {
        'class': NoSQLPlugin,
        'name': 'NoSQL Injection',
        'version': '2.0.0',
        'description': 'NoSQL injection detection for MongoDB, CouchDB, and more'
    }
}