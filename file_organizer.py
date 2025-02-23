import os
import shutil
import time
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import mimetypes
import hashlib
from collections import defaultdict

console = Console()

class SmartFileOrganizer:
    def __init__(self, directory):
        self.directory = Path(directory)
        # Comprehensive file format mapping
        self.known_formats = {
            # Images
            'JPG': ['.jpg', '.jpeg', '.jpe', '.jif', '.jfif'],
            'PNG': ['.png'],
            'GIF': ['.gif'],
            'RAW': ['.raw', '.arw', '.cr2', '.nrw', '.k25', '.dng'],
            'PSD': ['.psd', '.psb'],
            'AI': ['.ai'],
            'TIFF': ['.tiff', '.tif'],
            'BMP': ['.bmp'],
            'HEIC': ['.heic'],
            'SVG': ['.svg'],
            'WEBP': ['.webp'],
            'ICO': ['.ico'],
            
            # Video
            'MP4': ['.mp4', '.m4v', '.m4p'],
            'AVI': ['.avi'],
            'MOV': ['.mov', '.qt'],
            'WMV': ['.wmv'],
            'FLV': ['.flv', '.f4v', '.f4p', '.f4a', '.f4b'],
            'MKV': ['.mkv'],
            'WEBM': ['.webm'],
            '3GP': ['.3gp', '.3g2'],
            'MPEG': ['.mpeg', '.mpg', '.mpe', '.mpv'],
            
            # Audio
            'MP3': ['.mp3'],
            'WAV': ['.wav'],
            'FLAC': ['.flac'],
            'M4A': ['.m4a'],
            'AAC': ['.aac'],
            'OGG': ['.ogg', '.oga'],
            'WMA': ['.wma'],
            'MIDI': ['.midi', '.mid'],
            'AMR': ['.amr'],
            
            # Documents
            'PDF': ['.pdf'],
            'DOC': ['.doc', '.docx', '.docm'],
            'XLS': ['.xls', '.xlsx', '.xlsm'],
            'PPT': ['.ppt', '.pptx', '.pptm'],
            'TXT': ['.txt', '.text', '.md', '.markdown'],
            'RTF': ['.rtf'],
            'ODT': ['.odt'],
            'CSV': ['.csv'],
            'EPUB': ['.epub'],
            'MOBI': ['.mobi'],
            
            # Code
            'PY': ['.py', '.pyw', '.pyc', '.pyo', '.pyd'],
            'JAVA': ['.java', '.class', '.jar'],
            'JS': ['.js', '.jsx', '.mjs'],
            'HTML': ['.html', '.htm', '.xhtml'],
            'CSS': ['.css', '.scss', '.sass'],
            'PHP': ['.php', '.phtml', '.php3', '.php4', '.php5'],
            'CPP': ['.cpp', '.cc', '.cxx', '.c++', '.hpp'],
            'C': ['.c', '.h'],
            'GO': ['.go'],
            'TS': ['.ts', '.tsx'],
            'SQL': ['.sql'],
            'R': ['.r', '.R'],
            
            # Design & Creative
            'CUBE': ['.cube'],
            'LUT': ['.lut'],
            '3DL': ['.3dl'],
            'ICC': ['.icc', '.icm'],
            'DCP': ['.dcp'],
            'XMP': ['.xmp'],
            'PRESET': ['.xmp', '.lrtemplate', '.dng'],
            'FIG': ['.fig'],
            'XD': ['.xd'],
            
            # Archives
            'ZIP': ['.zip', '.zipx'],
            'RAR': ['.rar'],
            '7Z': ['.7z'],
            'TAR': ['.tar', '.gz', '.bz2', '.xz'],
            'ISO': ['.iso'],
            
            # Executables & Installers
            'EXE': ['.exe', '.msi', '.msix'],
            'APP': ['.app'],
            'DMG': ['.dmg'],
            'APK': ['.apk', '.aab'],
            'IPA': ['.ipa'],
            
            # Development
            'GIT': ['.git'],
            'CONFIG': ['.config', '.conf', '.cfg', '.ini'],
            'ENV': ['.env', '.env.local', '.env.development'],
            'YAML': ['.yml', '.yaml'],
            'JSON': ['.json'],
            'XML': ['.xml'],
            'LOG': ['.log'],
            
            # Fonts
            'TTF': ['.ttf'],
            'OTF': ['.otf'],
            'WOFF': ['.woff', '.woff2'],
            
            # 3D & CAD
            'STL': ['.stl'],
            'OBJ': ['.obj'],
            'FBX': ['.fbx'],
            'BLEND': ['.blend'],
            '3DS': ['.3ds'],
            
            # Database
            'DB': ['.db', '.sqlite', '.sqlite3'],
            'MDB': ['.mdb', '.accdb'],
            
            # Game Development
            'UNITY': ['.unity', '.prefab', '.asset'],
            'UE': ['.uasset', '.umap'],
            
            # Virtual Machines
            'VMDK': ['.vmdk'],
            'VDI': ['.vdi'],
            'OVA': ['.ova'],
            
            # Cryptocurrency
            'WALLET': ['.wallet'],
            'DAT': ['.dat'],
            
            # Capture One & Other
            'COP': ['.cop'],
            'COF': ['.cof'],
            'CR3': ['.cr3'],
            'RAF': ['.raf'],
            'RW2': ['.rw2'],
            
            # Adobe & Creative
            'INDD': ['.indd'],
            'AEP': ['.aep'],
            'PRPROJ': ['.prproj'],
        }
        
        # Reverse mapping for quick extension lookup
        self.extension_map = {}
        for category, extensions in self.known_formats.items():
            for ext in extensions:
                self.extension_map[ext] = category
        
        self.mime_categories = {
            'image': 'Images',
            'video': 'Videos',
            'audio': 'Audio',
            'text': 'Documents'
        }
        self.duplicate_hashes = defaultdict(list)

    def get_file_category(self, file_path):
        """Smart file categorization with extended format support"""
        extension = file_path.suffix.lower()
        
        # Check in known extensions
        if extension in self.extension_map:
            return self.extension_map[extension]
        
        # If no extension or unknown extension
        if not extension:
            mime_type = mimetypes.guess_type(file_path)[0]
            if mime_type:
                for mime_prefix, category in self.mime_categories.items():
                    if mime_prefix in mime_type:
                        return category
            
            # Try to detect file type by content
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(512)
                    # Check for binary files
                    if b'\x00' in header:
                        return 'Binaries'
                    # Try to detect text files
                    try:
                        header.decode('utf-8')
                        return 'Text'
                    except:
                        return 'Binary'
            except:
                pass
            
            return 'No_Extension'
        
        # Unknown extension
        return extension[1:].upper()

    def get_date_category(self, timestamp):
        """Organize files by year and month"""
        file_date = datetime.fromtimestamp(timestamp)
        year = str(file_date.year)
        month = file_date.strftime("%B")  # Full month name
        return f"{year}/{month}"

    def calculate_file_hash(self, file_path):
        """Calculate file hash for duplicate detection"""
        hasher = hashlib.md5()
        try:
            with open(file_path, 'rb') as f:
                buf = f.read(65536)  # Read in 64kb chunks
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = f.read(65536)
        except Exception:
            return None
        return hasher.hexdigest()

    def organize_files(self, by_date=False, remove_duplicates=True, optimize_space=True):
        """Smart file organization with multiple options"""
        stats = {
            'moved': 0,
            'duplicates': 0,
            'space_saved': 0,
            'errors': 0,
            'years_processed': set()
        }

        with Progress() as progress:
            task = progress.add_task("[cyan]Analyzing files...", total=len(list(self.directory.glob('**/*'))))

            # First pass: Analyze files and detect duplicates
            for file_path in self.directory.glob('**/*'):
                progress.update(task, advance=1)
                if not file_path.is_file():
                    continue

                file_hash = self.calculate_file_hash(file_path)
                if file_hash:
                    self.duplicate_hashes[file_hash].append(file_path)

            # Second pass: Organize files
            progress.update(task, total=len(list(self.directory.glob('**/*'))))
            for file_path in self.directory.glob('**/*'):
                if not file_path.is_file():
                    continue

                try:
                    # Get file categorization
                    category = self.get_file_category(file_path)
                    if by_date:
                        date_cat = self.get_date_category(file_path.stat().st_mtime)
                        category = f"{category}/{date_cat}"
                        year = date_cat.split('/')[0]
                        stats['years_processed'].add(year)

                    # Create destination folder
                    dest_folder = self.directory / category
                    dest_folder.mkdir(parents=True, exist_ok=True)

                    # Handle duplicates
                    file_hash = self.calculate_file_hash(file_path)
                    if remove_duplicates and len(self.duplicate_hashes[file_hash]) > 1:
                        if file_path != self.duplicate_hashes[file_hash][0]:
                            stats['duplicates'] += 1
                            stats['space_saved'] += file_path.stat().st_size
                            file_path.unlink()
                            continue

                    # Move file
                    new_path = dest_folder / file_path.name
                    if new_path.exists():
                        new_path = dest_folder / f"{file_path.stem}_{int(time.time())}{file_path.suffix}"
                    
                    shutil.move(str(file_path), str(new_path))
                    stats['moved'] += 1
                    console.print(f"[green]Organized:[/green] {file_path.name} → {category}")

                except Exception as e:
                    stats['errors'] += 1
                    console.print(f"[red]Error processing {file_path.name}: {str(e)}[/red]")

        return stats

    def optimize_storage(self):
        """Optimize storage space"""
        stats = {'compressed': 0, 'space_saved': 0}
        
        # Find large files that could be compressed
        large_files = [f for f in self.directory.glob('**/*') 
                      if f.is_file() and f.stat().st_size > 10_000_000]  # Files > 10MB

        for file_path in large_files:
            try:
                # Create archives folder
                archive_dir = self.directory / 'Compressed'
                archive_dir.mkdir(exist_ok=True)

                # Compress large files
                archive_name = archive_dir / f"{file_path.stem}.zip"
                shutil.make_archive(str(archive_name.with_suffix('')), 'zip', 
                                  str(file_path.parent), str(file_path.name))
                
                # If compression was successful, remove original
                if archive_name.exists():
                    original_size = file_path.stat().st_size
                    compressed_size = archive_name.stat().st_size
                    
                    if compressed_size < original_size:
                        file_path.unlink()
                        stats['compressed'] += 1
                        stats['space_saved'] += (original_size - compressed_size)
                        console.print(f"[green]Compressed:[/green] {file_path.name}")

            except Exception as e:
                console.print(f"[red]Compression failed for {file_path.name}: {str(e)}[/red]")

        return stats

    def show_statistics(self, stats):
        """Display detailed statistics"""
        table = Table(title="Smart Organization Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")

        table.add_row("Files Organized", str(stats['moved']))
        table.add_row("Duplicates Removed", str(stats['duplicates']))
        table.add_row("Space Saved", f"{stats['space_saved'] / (1024*1024):.2f} MB")
        if 'years_processed' in stats and stats['years_processed']:
            table.add_row("Years Processed", ", ".join(sorted(stats['years_processed'])))
        table.add_row("Errors Encountered", str(stats['errors']))

        console.print(table)

def main():
    console.print("\n[bold cyan]🤖 Smart File Organizer AI[/bold cyan]")
    console.print("Intelligent file organization and optimization system\n")

    while True:
        dir_path = input("Enter directory path to organize: ").strip()
        if os.path.exists(dir_path):
            break
        console.print("[red]Directory not found! Please try again.[/red]")

    # Get user preferences
    by_date = console.input("[cyan]Organize by date as well? (y/n): [/cyan]").lower() == 'y'
    remove_dupes = console.input("[cyan]Remove duplicate files? (y/n): [/cyan]").lower() == 'y'
    optimize = console.input("[cyan]Optimize storage space? (y/n): [/cyan]").lower() == 'y'

    # Create and run organizer
    organizer = SmartFileOrganizer(dir_path)
    
    console.print("\n[yellow]Starting smart organization...[/yellow]")
    stats = organizer.organize_files(by_date, remove_dupes, optimize)

    if optimize:
        console.print("\n[yellow]Optimizing storage space...[/yellow]")
        opt_stats = organizer.optimize_storage()
        stats['space_saved'] += opt_stats['space_saved']

    console.print("\n[bold]Organization Summary:[/bold]")
    organizer.show_statistics(stats)

if __name__ == "__main__":
    main() 