# Notes
This repository is a way to store notes, references and knowledges through Obsidian.
Obsidian creates a markdown file by page and builds a graph from links and backlinks.
Current architecture is based on those features to build up a graph from my notes, everything is open to modification according to future needs or enhancement.

## Architecture
- Each file is a node, either empty (generated from a tag), with the basic template or with notes
- Each file is at least a backlink from another node
- Each file aims to become a fully featured node
- Everything can move any time if relevant for storage and organization

## Template
A fully featured node is based on this template:
```md
- URL: <url for documentation or online resource to retrieve information>
- Description: <quick description to understand key points>
- Platforms: <either os or language concerned by the node>
- Category: <either Tools, Technique or Documentation>
- Tags: <all backlinks, even it does not exist, it creates backlinks>
```
In a perfect world we want everything to be correctly filled in. In the real world, we want to keep going and come back after to clean everything. 

## Notes
After template free notes are stored, not required but if found relevant or out of documentation scope, it is added to keep tracks.

## How to use
Open a vault in the database folder from Obsidian
