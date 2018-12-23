OAuth 2.0 Google Provider Changelog

## 3.0.0 - ???

### Changed

- Update to latest version of Google OAuth
- Use only OpenID Connect for user details

### Fixed

- Correct handling of selecting from multiple user accounts, #45
- Prevent conflict when using prompt option, #42

### Added

- Support additional scopes at construction

### Removed

- Dropped support for Google+ user details, #34 and #63

## 2.2.0 - 2018-03-19

### Added

- Hosted domain validation, #54 by @pradtke

## 2.1.0 - 2018-03-09

### Added

- OpenID Connect support, #48 by @pradtke

## 2.0.0 - 2017-01-24

### Added

- PHP 7.1 support

### Removed

- Dropped PHP 5.5 support

## 1.0.0 - 2015-08-12

- Initial release