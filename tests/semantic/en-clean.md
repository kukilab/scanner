# Changelog formatter

Turns a list of merged pull requests into a changelog section.

## Usage

Give the skill the list of pull request titles. It groups them under Added, Changed and Fixed, keeps the pull request numbers and writes the result to `CHANGELOG.md` in the project folder.

## Limits

It reads and writes only inside the project folder. It never pushes, tags or publishes anything: that stays with you.
