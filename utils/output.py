"""
Output formatting utilities
"""

import json
import csv
from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table
from rich.tree import Tree


console = Console()


def print_json(data: Dict[Any, Any]):
    """Pretty print JSON"""
    console.print_json(json.dumps(data, indent=2))


def print_table(data: Dict[str, List[Dict]], title: str = "Results"):
    """Print results as table"""
    table = Table(title=title)
    
    if not data:
        console.print("[yellow]No data to display[/yellow]")
        return
    
    # Add columns based on first item
    first_key = list(data.keys())[0]
    if data[first_key]:
        first_item = data[first_key][0]
        for key in first_item.keys():
            table.add_column(key.capitalize(), style="cyan")
    
    for category, items in data.items():
        for item in items:
            row = [str(item.get(k, '')) for k in first_item.keys()]
            table.add_row(*row)
    
    console.print(table)


def print_tree(data: Dict[str, List[Dict]], title: str = "Results"):
    """Print results as tree"""
    tree = Tree(f"[bold]{title}[/bold]")
    
    for category, items in data.items():
        cat_branch = tree.add(f"[cyan]{category}[/cyan] ({len(items)})")
        for item in items:
            item_str = ", ".join([f"{k}: {v}" for k, v in item.items()])
            cat_branch.add(f"[green]{item_str}[/green]")
    
    console.print(tree)


def save_json(data: Dict[Any, Any], filepath: str):
    """Save data as JSON"""
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    console.print(f"[green]Saved to {filepath}[/green]")


def save_csv(data: Dict[str, List[Dict]], filepath: str):
    """Save data as CSV"""
    with open(filepath, 'w', newline='') as f:
        writer = None
        for category, items in data.items():
            if items:
                if writer is None:
                    fieldnames = ['category'] + list(items[0].keys())
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                
                for item in items:
                    row = {'category': category}
                    row.update(item)
                    writer.writerow(row)
    console.print(f"[green]Saved to {filepath}[/green]")


def save_txt(data: Dict[str, List[Dict]], filepath: str):
    """Save data as plain text"""
    with open(filepath, 'w') as f:
        for category, items in data.items():
            f.write(f"=== {category.upper()} ===\n")
            for item in items:
                f.write(f"  {', '.join([f'{k}: {v}' for k, v in item.items()])}\n")
            f.write("\n")
    console.print(f"[green]Saved to {filepath}[/green]")