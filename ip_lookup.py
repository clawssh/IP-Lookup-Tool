import requests
import socket
import json
import argparse
import whois
import dns.resolver
from datetime import datetime
from typing import Dict, Any
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Back, Style
import sys

# Initialize colorama for cross-platform color support
init()

ASCII_BANNER = f"""{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║   _____ _____    _                _                 ™        ║
║  |_   _|  __ \\  | |              | |                        ║
║    | | | |__) | | |     ___   ___| | ___   _ _ __          ║
║    | | |  ___/  | |    / _ \\ / _ \\ |/ / | | | '_ \\         ║
║   _| |_| |      | |___| (_) |  __/   <| |_| | |_) |        ║
║  |_____|_|      |______\\___/ \\___|_|\\_\\\\__,_| .__/         ║
║                                             | |              ║
║                                             |_|              ║
║{Fore.RED}                    By ClawSSH{Fore.CYAN}                           ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
{Fore.YELLOW}[*] Usage example: python ip_lookup.py 8.8.8.8{Style.RESET_ALL}
"""

class TerminalFormatter:
    @staticmethod
    def section_header(text: str) -> str:
        return f"\n{Fore.RED}╔{'═' * 48}╗\n{Fore.WHITE}{Style.BRIGHT} {text}{Style.RESET_ALL}\n{Fore.RED}╚{'═' * 48}╝{Style.RESET_ALL}\n"

    @staticmethod
    def field(name: str, value: str, color: str = Fore.WHITE) -> str:
        return f"{Fore.CYAN}▶ {Fore.YELLOW}{name}: {color}{value}{Style.RESET_ALL}"

    @staticmethod
    def warning(text: str) -> str:
        return f"{Fore.RED}⚠ {text}{Style.RESET_ALL}"

    @staticmethod
    def success(text: str) -> str:
        return f"{Fore.GREEN}✓ {text}{Style.RESET_ALL}"

    @staticmethod
    def info(text: str) -> str:
        return f"{Fore.BLUE}ℹ {text}{Style.RESET_ALL}"

class IPLookupTool:
    def __init__(self):
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 3
        self.dns_resolver.lifetime = 3
        
    def get_basic_info(self, ip: str) -> Dict[str, Any]:
        """Get basic IP information using ip-api.com (free, no API key needed)"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,continent,country,regionName,city,lat,lon,isp,org,as,mobile,proxy,hosting")
            return response.json()
        except Exception as e:
            return {"error": f"Failed to get basic info: {str(e)}"}

    def get_dns_info(self, ip: str) -> Dict[str, Any]:
        """Get comprehensive DNS information"""
        dns_info = {}
        try:
            # Get forward and reverse DNS
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                dns_info["hostname"] = hostname
            except:
                dns_info["hostname"] = "No hostname found"

            # Get common DNS records if hostname exists
            if dns_info["hostname"] != "No hostname found":
                record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS']
                for record_type in record_types:
                    try:
                        answers = self.dns_resolver.resolve(dns_info["hostname"], record_type)
                        dns_info[f"{record_type}_records"] = [str(rdata) for rdata in answers]
                    except:
                        dns_info[f"{record_type}_records"] = []

            return dns_info
        except Exception as e:
            return {"error": f"DNS lookup failed: {str(e)}"}

    def get_threat_intel(self, ip: str) -> Dict[str, Any]:
        """Get threat intelligence data from various free sources"""
        try:
            # Check against Tor exit nodes
            tor_response = requests.get("https://check.torproject.org/exit-addresses")
            is_tor = ip in tor_response.text

            # Check against free threat intel feeds
            response = requests.get(f"https://api.greynoise.io/v3/community/{ip}", 
                                  headers={"Accept": "application/json"})
            grey_noise = response.json()

            return {
                "is_tor_exit": is_tor,
                "grey_noise_data": grey_noise
            }
        except Exception as e:
            return {"error": f"Failed to get threat intel: {str(e)}"}

    def get_whois_info(self, ip: str) -> Dict[str, Any]:
        """Get WHOIS information"""
        try:
            w = whois.whois(ip)
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "org": w.org,
                "emails": w.emails
            }
        except Exception as e:
            return {"error": f"WHOIS lookup failed: {str(e)}"}

    def full_lookup(self, ip: str) -> Dict[str, Any]:
        """Perform a full lookup using all available services in parallel"""
        with ThreadPoolExecutor(max_workers=4) as executor:
            # Run all lookups in parallel
            basic_future = executor.submit(self.get_basic_info, ip)
            dns_future = executor.submit(self.get_dns_info, ip)
            threat_future = executor.submit(self.get_threat_intel, ip)
            whois_future = executor.submit(self.get_whois_info, ip)

            results = {
                "timestamp": datetime.now().isoformat(),
                "ip_address": ip,
                "basic_info": basic_future.result(),
                "dns_info": dns_future.result(),
                "threat_intel": threat_future.result(),
                "whois_info": whois_future.result()
            }
            
            # Add summary section
            results["summary"] = self._create_summary(results)
            return results

    def _create_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Create a summary of the most important findings"""
        summary = {
            "location": "Unknown",
            "organization": "Unknown",
            "is_suspicious": False,
            "risk_factors": []
        }

        basic = results.get("basic_info", {})
        if "country" in basic and "city" in basic:
            summary["location"] = f"{basic.get('city', '')}, {basic.get('country', '')}"
        if "org" in basic:
            summary["organization"] = basic.get("org")

        # Check for suspicious indicators
        if basic.get("proxy", False):
            summary["risk_factors"].append("Proxy detected")
        if results.get("threat_intel", {}).get("is_tor_exit"):
            summary["risk_factors"].append("Tor exit node")
        
        grey_noise = results.get("threat_intel", {}).get("grey_noise_data", {})
        if grey_noise.get("classification") == "malicious":
            summary["risk_factors"].append("Reported malicious activity")

        summary["is_suspicious"] = len(summary["risk_factors"]) > 0
        return summary

def print_results_pretty(results: Dict[str, Any]):
    print(ASCII_BANNER)
    
    print(TerminalFormatter.section_header("IP INFORMATION"))
    
    # Handle both basic and full lookup results
    if isinstance(results, dict) and "status" in results:
        # Basic lookup results
        print(TerminalFormatter.field("IP Address", results.get("query", "Unknown"), Fore.GREEN))
        if "country" in results:
            print(TerminalFormatter.field("Country", results["country"]))
        if "city" in results:
            print(TerminalFormatter.field("City", results["city"]))
        if "isp" in results:
            print(TerminalFormatter.field("ISP", results["isp"]))
        if "as" in results:
            print(TerminalFormatter.field("AS", results["as"]))
        if "proxy" in results:
            proxy_status = "Yes" if results["proxy"] else "No"
            color = Fore.RED if results["proxy"] else Fore.GREEN
            print(TerminalFormatter.field("Proxy", proxy_status, color))
    else:
        # Full lookup results
        print(TerminalFormatter.field("IP Address", results["ip_address"], Fore.GREEN))
        print(TerminalFormatter.field("Timestamp", results["timestamp"], Fore.BLUE))

    if "summary" in results:
        print(TerminalFormatter.section_header("SUMMARY"))
        summary = results["summary"]
        print(TerminalFormatter.field("Location", summary["location"]))
        print(TerminalFormatter.field("Organization", summary["organization"]))
        
        if summary["risk_factors"]:
            print("\n" + TerminalFormatter.warning("RISK FACTORS DETECTED"))
            for risk in summary["risk_factors"]:
                print(f"{Fore.RED}  • {risk}{Style.RESET_ALL}")
        else:
            print("\n" + TerminalFormatter.success("No Risk Factors Detected"))

    if "basic_info" in results and not isinstance(results["basic_info"], dict):
        basic = results["basic_info"]
        print(TerminalFormatter.section_header("BASIC INFORMATION"))
        if "isp" in basic:
            print(TerminalFormatter.field("ISP", basic["isp"]))
        if "as" in basic:
            print(TerminalFormatter.field("AS", basic["as"]))
        if "proxy" in basic:
            proxy_status = "Yes" if basic["proxy"] else "No"
            color = Fore.RED if basic["proxy"] else Fore.GREEN
            print(TerminalFormatter.field("Proxy", proxy_status, color))

    if "dns_info" in results:
        print(TerminalFormatter.section_header("DNS INFORMATION"))
        dns = results["dns_info"]
        if isinstance(dns, dict):
            print(TerminalFormatter.field("Hostname", dns.get("hostname", "Not found")))
            for record_type in ['A', 'AAAA', 'MX', 'TXT', 'NS']:
                records = dns.get(f"{record_type}_records", [])
                if records:
                    print(f"\n{Fore.CYAN}[{record_type} Records]{Style.RESET_ALL}")
                    for record in records:
                        print(f"  {Fore.WHITE}• {record}{Style.RESET_ALL}")

    if "threat_intel" in results:
        print(TerminalFormatter.section_header("THREAT INTELLIGENCE"))
        threat = results["threat_intel"]
        if isinstance(threat, dict):
            tor_status = "Yes" if threat.get("is_tor_exit") else "No"
            color = Fore.RED if threat.get("is_tor_exit") else Fore.GREEN
            print(TerminalFormatter.field("Tor Exit Node", tor_status, color))
            
            grey_noise = threat.get("grey_noise_data", {})
            if "classification" in grey_noise:
                color = Fore.RED if grey_noise["classification"] == "malicious" else Fore.GREEN
                print(TerminalFormatter.field("GreyNoise Classification", 
                                           grey_noise["classification"].title(), 
                                           color))

def is_valid_ip(ip: str) -> bool:
    """Validate IP address format"""
    try:
        parts = ip.split('.')
        return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
    except (AttributeError, TypeError, ValueError):
        return False

def interactive_mode():
    """Interactive mode for the IP lookup tool"""
    print(ASCII_BANNER)
    print(f"{Fore.CYAN}=== Interactive Mode ==={Style.RESET_ALL}\n")
    
    # Get IP address
    while True:
        ip = input(f"{Fore.YELLOW}Enter IP address to lookup: {Style.RESET_ALL}")
        if is_valid_ip(ip):
            break
        print(TerminalFormatter.warning("Invalid IP address format. Please try again."))
    
    # Ask for lookup type
    print(f"\n{Fore.YELLOW}Select lookup type:{Style.RESET_ALL}")
    print("1. Basic lookup (faster)")
    print("2. Full lookup (detailed)")
    while True:
        choice = input(f"{Fore.YELLOW}Enter choice (1/2): {Style.RESET_ALL}")
        if choice in ['1', '2']:
            break
        print(TerminalFormatter.warning("Invalid choice. Please enter 1 or 2."))
    
    # Ask about saving results
    save = input(f"\n{Fore.YELLOW}Save results to file? (y/N): {Style.RESET_ALL}").lower()
    output_file = None
    if save.startswith('y'):
        output_file = input(f"{Fore.YELLOW}Enter filename (e.g., results.json): {Style.RESET_ALL}")
    
    return {
        'ip': ip,
        'basic': choice == '1',
        'output': output_file,
        'format': 'text'
    }

def main():
    # Show interactive mode if no arguments provided
    if len(sys.argv) == 1:
        args = argparse.Namespace(**interactive_mode())
    else:
        parser = argparse.ArgumentParser(
            description='Advanced IP Lookup Tool',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  python ip_lookup.py 8.8.8.8                 # Basic lookup with pretty output
  python ip_lookup.py 8.8.8.8 --format json   # JSON output
  python ip_lookup.py 8.8.8.8 -o results.json # Save to file
  python ip_lookup.py 8.8.8.8 --basic         # Basic lookup only
            """
        )
        parser.add_argument('ip', help='IP address to lookup (e.g., 8.8.8.8)')
        parser.add_argument('--output', '-o', help='Output file (JSON)')
        parser.add_argument('--basic', '-b', action='store_true', help='Basic lookup only')
        parser.add_argument('--format', '-f', choices=['json', 'text'], default='text', 
                           help='Output format (default: text)')
        args = parser.parse_args()

    tool = IPLookupTool()
    
    try:
        if args.basic:
            print(TerminalFormatter.info("Starting basic lookup..."))
            results = tool.get_basic_info(args.ip)
            if "status" in results and results["status"] == "fail":
                raise Exception(results.get("message", "Lookup failed"))
        else:
            print(TerminalFormatter.info("Starting full lookup, this may take a few seconds..."))
            results = tool.full_lookup(args.ip)
        
        # Format and display results
        if args.format == 'json':
            print(json.dumps(results, indent=2))
        else:
            print_results_pretty(results)
        
        # Save to file if specified
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(TerminalFormatter.success(f"\nResults saved to {args.output}"))
            
    except Exception as e:
        print(TerminalFormatter.warning(f"An error occurred: {str(e)}"))
        print(TerminalFormatter.info("Try using --basic flag if the error persists"))

if __name__ == "__main__":
    main() 