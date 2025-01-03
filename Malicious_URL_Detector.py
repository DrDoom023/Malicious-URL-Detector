import re
import urllib.parse
import pandas as pd
import tldextract
import datetime
import logging

from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from termcolor import colored
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

# This script combines pattern recognition and machine learning to determine whether the URLs entered by the user are malicious or safe.

malicious_log = []  
safe_log = []      
log = []  

print(colored("------------------------------------------------------------------------", "cyan"))
print(colored("                     Malicious URL Detector", "yellow", attrs=["bold"]))
print(colored("This program will detect malicious URLs.", "white"))
print(colored("You can classify a single URL, scan a file containing multiple URLs, or view logs.", "white")) 
print(colored("------------------------------------------------------------------------", "cyan"))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('url_detector.log'),
        logging.StreamHandler()
    ]
)

@dataclass
class URLData:
    url: str
    classification: str
    timestamp: datetime.datetime
    confidence_score: float

class URLLogger:
    def __init__(self, log_file: str = 'url_analysis.json'):
        self.log_file = Path(log_file)
        self.malicious_urls: List[URLData] = []
        self.safe_urls: List[URLData] = []
        self._load_logs()

    def _load_logs(self) -> None:
        if self.log_file.exists():
            try:
                data = pd.read_json(self.log_file)
            
                logging.info(f"Loaded {len(data)} log entries")
            except Exception as e:
                logging.error(f"Error loading logs: {e}")

    def add_url(self, url_data: URLData) -> None:
        """Add a new URL to the appropriate log"""
        if url_data.classification == "malicious":
            self.malicious_urls.append(url_data)
        else:
            self.safe_urls.append(url_data)
        self._save_logs()

    def _save_logs(self) -> None:                         # Save file in JSON
        try:
            data = {
                'malicious': [vars(url) for url in self.malicious_urls],
                'safe': [vars(url) for url in self.safe_urls]
            }
            pd.DataFrame(data).to_json(self.log_file)
        except Exception as e:
            logging.error(f"Error saving logs: {e}")

class URLFeatureExtractor:
    def __init__(self):
        self.suspicious_tlds = {'tk', 'ga', 'ml', 'cf', 'gq', 'top', 'xyz', 'work', 'party', 'info', 'wang'}
        
    def extract_features(self, url: str) -> Dict:
        """Extract features from URL for classification"""
        try:
            features = {}
            parsed = urllib.parse.urlparse(url)
            extracted = tldextract.extract(url)
            
            # URL structure features
            features.update({
                'length': len(url),
                'num_dots': url.count('.'),
                'num_digits': sum(c.isdigit() for c in url),
                'num_special_chars': len(re.findall(r'[^a-zA-Z0-9.]', url)),
                'domain_length': len(extracted.domain),
                'subdomain_length': len(extracted.subdomain),
                'has_www': int(extracted.subdomain == 'www'),
                'tld_in_suspicious': int(extracted.suffix in self.suspicious_tlds),
                'path_length': len(parsed.path),
                'query_length': len(parsed.query),
                'has_port': int(bool(parsed.port)),
                'has_https': int(parsed.scheme == 'https'),
                'num_subdomains': len(extracted.subdomain.split('.')),
                'has_credentials': int('@' in url),
                'has_multiple_slashes': int('//' in parsed.path)
            })
            
            # Additional security features
            features.update({
                'has_ip_address': int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', extracted.domain))),
                'has_hex_chars': int(bool(re.search(r'%[0-9a-fA-F]{2}', url))),
                'has_at_symbol': int('@' in url),
                'has_javascript': int(bool(re.search(r'javascript:|javascript;', url.lower())))
            })
            
            return features
        except Exception as e:
            logging.error(f"Error extracting features from URL {url}: {e}")
            return {}


class UserInput:
    def __init__(self):
        self.history = []  
        self.commands = {
            'back': self.back_command,
            'exit': self.exit_command
        }
    
    def add_command(self, command_name, command_function):
        self.commands[command_name] = command_function
    
    def get_input(self, prompt):
        user_input = input(prompt).strip().lower()
        return user_input 

    def back_command(self):
        if self.history:
            previous_question = self.history.pop()
            print(f"Returning to the previous question: {previous_question}")
            return None  
        else:
            print("No previous question to return to!")
            return None  

    def exit_command(self):
        print("Exiting the program. Goodbye!")
        exit()  
        return None 

# Rule-Based Detection
def is_malicious(input_str):
    trusted_domains = ['youtube.com', 'google.com', 'amazon.com', 'github.com', 'microsoft.com', 'chatgpt.com', 'instagram.com', 'whatsapp.com', 'duckduckgo.com', 'weather.com',
                       'facebook.com','netflix.com', 'tubitv.com', 'meta.ai', 'reddit.com', 'tryhackme.com', 'outlook.live.com', 'udemy.com', 'hackthebox.com', 'x.com', 'wikipedia.org', 'tiktok.com', 'ebay.com']
    for domain in trusted_domains:
        if domain in input_str:
            return "non-malicious link"  

    malicious_patterns = [
        r"(?i)(\.tk|\.ga|\.ml|\.cf|\.functions|\.biz|\..no-ip|\.zapto|\.systes|\.server|\.org|\.webhp|\.gq)$",          # Free domain extensions often used for scams
        r"(?i)\.php$",                              # PHP files
        r"(?i)\.exe$",                              # Executable files
        r"(?i)\.asp$",                              # ASP files
        r"(?i)\.aspx$",                             # ASPX files
        r"(?i)\.jpg$",                              # JPG files
        r"(?i)\.shell$",                            # Shell scripts
        r"(?i)\.n$",                                # Suspicious .n extension
        r"(?i)php$",                                # URLs with PHP in the path
        r"(?i)feed$",                               # URLs with feed in the path
        r"(?i)docs$",                               # URLs with docs in the path
        r"(?i)info$",                               # URLs with info in the path
        r"(?i)forum$",                              # URLs with forum in the path
        r"(?i)advice$",                             # URLs with advice in the path
        r"(?i)token=",                              # Tokens in URLs
        r"(?i)redirect=",                           # Open redirect attempts
        r"(?i)\bid=\d{10,}\b",                      # Numeric ID patterns
        r"(?i)\w+\.\w+\.\w+\.\w+",                  # Multiple subdomains
        r"(?i)\.exe$",                              # Executable files
        r"(?i)\.jpg$",                              # JPG files
        r"(?i)\.gif$",                              # GIF files
        r"(?i)\.png$",                              # PNG files
        r"(?i)\.bmp$",                              # BMP files
        r"(?i)\.zip$",                              # ZIP files
        r"(?i)\.rar$",                              # RAR files
        r"(?i)\.tar$",                              # TAR files
        r"(?i)\.gz$",                               # GZ files
        r"(?i)\.7z$",                               # 7z files
        r"(?i)\.dmg$",                              # DMG files
        r"(?i)\.iso$",                              # ISO files
        r"(?i)\.js$",                               # JavaScript files
        r"(?i)\.jar$",                              # JAR files
        r"(?i)\.apk$",                              # APK files
        r"(?i)\.dll$",                              # DLL files
        r"(?i)\.cmd$",                              # CMD files
        r"(?i)\.bat$",                              # BAT files
        r"(?i)\.sh$",                               # SH files
        r"(?i)\.vbs$",                              # VBS files
        r"(?i)http://",                             # HTTP links
        r"(?i)https://",                            # HTTPS links
        r"(?i)\.top$",                              # .top TLD
        r"(?i)\.xyz$",                              # .xyz TLD
        r"(?i)\.rest$",                             # .rest TLD
        r"(?i)\.fit$",                              # .fit TLD
        r"(?i)\.wang$",                             # .wang TLD
        r"(?i)\.gdn$",                              # .gdn TLD
        r"(?i)\.work$",                             # .work TLD
        r"(?i)\.click$",                            # .click TLD
        r"(?i)\.loan$",                             # .loan TLD
        r"(?i)\.download$",                         # .download TLD
        r"(?i)\.racing$",                           # .racing TLD
        r"(?i)\bid=[^\s]+",                         # IDs in URLs
        r"(?i)://.*@",                              # Credentials in URLs
        r"(?i)(?:\.\.|%2e%2e)",                     # Directory traversal
        r"(?i)(?:cmd|powershell|rm|delete|shutdown|webhp|wiki)",  # Command execution
    ]

    for pattern in malicious_patterns:
        if re.search(pattern, input_str):
            return "malicious link"
    
    return "non-malicious link"


class URLClassifier:
    def __init__(self, urls=None, labels=None):
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5))
        self.model = MultinomialNB()
        self.feature_names = []

        if urls is not None and labels is not None:
            self.train_model(urls, labels)
        else:
            self.model_fitted = False  

    def train_model(self, urls, labels):
        if urls is None or labels is None or len(urls) != len(labels):
            raise ValueError("URLs and labels must be provided and must have the same length.")

        # Extract numerical features from URLs
        feature_dicts = [self.extract_features(url) for url in urls]
        numerical_features = pd.DataFrame(feature_dicts)
        self.feature_names = numerical_features.columns.tolist()  

      
        text_features = self.vectorizer.fit_transform(urls)
        text_features_df = pd.DataFrame(
            text_features.toarray(), columns=[f'text_{i}' for i in range(text_features.shape[1])]
        )

        X = pd.concat([numerical_features, text_features_df], axis=1)
        self.model.fit(X, labels)
        self.model_fitted = True  

        print("Model training complete.")

    def predict(self, url):
        if not hasattr(self, 'model_fitted') or not self.model_fitted:
            raise ValueError("Model is not trained yet. Please train the model before prediction.")

        features = pd.DataFrame([self.extract_features(url)])
        features = features.reindex(columns=self.feature_names, fill_value=0) 
        
    
        text_features = self.vectorizer.transform([url])
        text_features_df = pd.DataFrame(
            text_features.toarray(), columns=[f'text_{i}' for i in range(text_features.shape[1])]
        )
        X = pd.concat([features, text_features_df], axis=1)

     
        prediction = self.model.predict(X)[0]
        return "malicious link" if prediction == 1 else "non-malicious link"


    def extract_features(self, url):
        try:
            features = {}
            parsed = urllib.parse.urlparse(url)
            extracted = tldextract.extract(url)

            # Basic URL properties
            features['length'] = len(url)
            features['num_dots'] = url.count('.')
            features['num_digits'] = sum(c.isdigit() for c in url)
            features['num_special_chars'] = len(re.findall(r'[^a-zA-Z0-9.]', url))
            features['domain_length'] = len(extracted.domain)
            features['subdomain_length'] = len(extracted.subdomain)
            features['has_www'] = extracted.subdomain == 'www'
            features['tld_in_suspicious'] = extracted.suffix in self.suspicious_tlds
            features['path_length'] = len(parsed.path)
            features['query_length'] = len(parsed.query)
            features['fragment_length'] = len(parsed.fragment)
            features['has_port'] = bool(parsed.port)

            features['has_https'] = parsed.scheme == 'https'
            features['num_subdomains'] = len(extracted.subdomain.split('.'))
            features['has_credentials'] = '@' in url
            features['has_multiple_slashes'] = '//' in parsed.path
            
            # BEHAVIORAL FEATURES 
            features['hour_of_day'] = datetime.datetine.now().hour
            features['day_of_week'] = datetime.datetime.now().weekday()
            features['referrer'] = 1 if parsed.netloc else 0
            
            return features
        except Exception:
            return {}

    def classification_of_url(self, url):
        rule_result = is_malicious(url)
        if rule_result == "malicious link":
            return "malicious link"  

     
        prediction = self.predict(url)
        return prediction  
    
    def scan_file_for_links(self, file_path):
        try:
            url_mapping = {}
            
            with open(file_path, 'r') as file:
                print("\nScanning links in the file...\n")
                
                for i, link in enumerate(file, start=1):
                    link = link.strip()
                    if not link:
                        continue
                    
                    url_mapping[i] = link
                    result = self.classification_of_url(link)
                    
                   
                    is_malicious = result == "malicious link"
                    
                    if is_malicious:
                        print(f"{i}. {link} -> {colored('malicious link', 'red')}")
                    else:
                        print(f"{i}. {link} -> {colored('non-malicious link', 'green')}")

            while True:
                rescan = input("\nEnter a line number to rescan (or 'done' to finish current scan) ").strip().lower()
                
                if rescan == 'done':
                    break
                
                try:
                    line_num = int(rescan)
                    if line_num in url_mapping:
                        url = url_mapping[line_num]
                        print(f"\nRescanning URL from line {line_num}:")
                        result = self.classification_of_url(url)
                        
                        is_malicious = result == "malicious link"
                        
                        if is_malicious:
                            print(f"{line_num}. {url} -> {colored('malicious link', 'red')}")
                            print(colored("This URL appears to be malicious. Avoid using it!", "red"))
                        else:
                            print(f"{line_num}. {url} -> {colored('non-malicious link', 'green')}")
                            print(colored("This URL appears to be safe.", "green"))
                    else:
                        print(colored(f"Error: Line number {line_num} not found in the file.", "red"))
                except ValueError:
                    print(colored("Please enter a valid line number or 'done'.", "red"))
        
        except FileNotFoundError:
            print(colored("Error: File not found. Please provide a valid file path.", "red"))

        except Exception as e:
            print(colored(f"An error occurred while scanning the file: {e}", "red"))

def scan_file_for_links(self, file_path):
    try:
        with open(file_path, 'r') as file:
            for line in file:
                url = line.strip()
                result = self.classification_of_url(url)
                is_malicious = result == "malicious link"

                if is_malicious:
                    global malicious_log
                    malicious_log.append(url) 
                else:
                    global safe_log
                    safe_log.append(url)  

               
                if is_malicious:
                    print(f"\nThe URL '{url}' is classified as: {colored('malicious link', 'red')}")
                    print(colored("This URL appears to be malicious. Avoid using it!", "red"))
                else:
                    print(f"\nThe URL '{url}' is classified as: {colored('non-malicious link', 'green')}")
                    print(colored("This URL appears to be safe.", "green"))
    except Exception as e:
        print(colored(f"Error while scanning the file: {e}", "red"))

def main():
    urls = [

        # SAFE URLs 0 
        'https://google.com',
        'https://github.com',
        'https://yahoo.com',
        'https://youtube.com',
        'https://microsoft.com',
        'https://amazon.com',
        'https://bbc.com',
        'https://wikipedia.org',
        'https://tiktok.com',
        'https://hackthebox.com',
        'https://linkedin.com',
        'https://apple.com',
        'https://instagram.com',
        'https://stackoverflow.com',
        'https://reddit.com',
        'https://paypal.com',
        'https://chatgpt.com',
        'https://meta.ai',
        'https://tryhackme.com',
        'https://facebook.com',
        'https://whatsapp.com',
        'https://netflix.com',

        # MALICIOUS URLs1 
        'http://malicious-site.tk',
        'http://192.168.1.1/admin',
        'http://bank-secure-login.gq',
        'http://freeprizewinner.xyz',
        'http://phisingsite.com',
        'http://paypal-secure-login.win',
        'http://secure-login-gmail.top',
        'http://trojan-site.in',
        'http://fake-secure-banking.com',
        'http://password-reset-scams.site',
        'http://secure-login-fake.top',
        'http://free-viruses.com',
        'http://login-to-your-account.xyz',
        'http://hottraveljobs.com/forum/docs/info.php',
        'http://news.grouptumbler.com/news/feed.php',
        'http://info.leveldelta.com/php/text.php',
        'http://citroen-club.ch/n.exe',
        'http://zehir4.asp',
        'http://ZHC_Shell_1.0.aspx',
        'http://img851/2304/bismillahus.jpg',
        'http://himselp.net.in/css/acrord.exe',
        'http://www.skyslisten.com/help.html',
        'http://micro/advice.php',
        'sidisalim.myvnc.com',
        'www.google.com/webhp',
        'dzhacker15.no-ip.org',
        'adamdam.zapto.org',
        'microsoftsystem.sytes.net',
        'googlechrome.servegame.com'
    ]
    

    labels = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  
              1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,                
              1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]

  
    classifier = URLClassifier(urls, labels)
    print(colored("------------------------------------------------------------------------", "cyan"))

   
    malicious_log = []
    safe_log = []
    log = []

 
    stats = {
        'total_checks': 0,
        'malicious_detected': 0,
        'safe_detected': 0,
        'session_start': datetime.datetime.now()
    }

    while True:
        print("\nURL Malicious Detector Menu:")
        print("1. Check URL")
        print("2. Scan file")
        print("3. View Logs")
        print("4. View Statistics")  
        print("5. Export Logs")      
        print("6. Batch Analysis")   
        print("7. Quit")

        action = input("Choose an option (1-7): ").strip().lower()

        if action == '1':  
            user_url = input("Enter the URL to check (or type 'exit' to return to the main menu): ").strip()

            if user_url.lower() == 'exit':
                continue

            if not user_url.startswith(('http://', 'https://')):
                user_url = 'http://' + user_url
                print(colored("Notice: Added 'http://' prefix to URL", "yellow"))


            if user_url.startswith("http://"):
                print(colored("Warning: This is an HTTP link, which is less secure than HTTPS.", "yellow"))

            
            result = classifier.classification_of_url(user_url)
            timestamp = datetime.datetime.now()
            stats['total_checks'] += 1

            is_malicious = result == "malicious link"
            if is_malicious:
                stats['malicious_detected'] += 1
                print(f"\nThe URL '{user_url}' is classified as: {colored('malicious link', 'red')}")
                print(colored("This URL appears to be malicious. Avoid using it!", "red"))
                malicious_log.append({
                    'url': user_url,
                    'timestamp': timestamp,
                    'detection_method': 'single_check'
                })
            else:
                stats['safe_detected'] += 1
                print(f"\nThe URL '{user_url}' is classified as: {colored('non-malicious link', 'green')}")
                print(colored("This URL appears to be safe.", "green"))
                safe_log.append({
                    'url': user_url,
                    'timestamp': timestamp,
                    'detection_method': 'single_check'
                })

        elif action == '2': 
            file_path = input("Enter the file path containing URLs: ").strip()
            try:
                total_urls = 0
                malicious_count = 0
                with open(file_path, 'r') as file:
                    print("\nScanning file...")
                    urls_to_scan = [line.strip() for line in file if line.strip()]
                    total_urls = len(urls_to_scan)
                    
                    for i, url in enumerate(urls_to_scan, 1):
                        print(f"\nProcessing URL {i}/{total_urls}: {url}")
                        result = classifier.classification_of_url(url)
                        timestamp = datetime.datetime.now()
                        
                        stats['total_checks'] += 1
                        if result == "malicious link":
                            stats['malicious_detected'] += 1
                            malicious_count += 1
                            print(f"Classification: {colored('malicious link', 'red')}")
                            malicious_log.append({
                                'url': url,
                                'timestamp': timestamp,
                                'detection_method': 'file_scan',
                                'file_source': file_path
                            })
                        else:
                            stats['safe_detected'] += 1
                            print(f"Classification: {colored('non-malicious link', 'green')}")
                            safe_log.append({
                                'url': url,
                                'timestamp': timestamp,
                                'detection_method': 'file_scan',
                                'file_source': file_path
                            })
            
                print(f"\nScan Complete!")
                print(f"Total URLs scanned: {total_urls}")
                print(f"Malicious URLs found: {malicious_count}")
                print(f"Safe URLs found: {total_urls - malicious_count}")
                
            except Exception as e:
                print(colored(f"Error while scanning the file: {e}", "red"))

        elif action == '3':  
            print("\nMalicious URLs Log:")
            if malicious_log:
                for entry in malicious_log:
                    timestamp_str = entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                    print(f"- {entry['url']} [{colored('Malicious', 'red')}] - Detected: {timestamp_str}")
            else:
                print("No malicious URLs detected yet.")

            print("\nSafe URLs Log:")
            if safe_log:
                for entry in safe_log:
                    timestamp_str = entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                    print(f"- {entry['url']} [{colored('Safe', 'green')}] - Detected: {timestamp_str}")
            else:
                print("No safe URLs logged yet.")

        elif action == '4':  
            session_duration = datetime.datetime.now() - stats['session_start']
            print("\nSession Statistics:")
            print(f"Session Duration: {session_duration}")
            print(f"Total URLs Checked: {stats['total_checks']}")
            print(f"Malicious URLs Detected: {stats['malicious_detected']}")
            print(f"Safe URLs Detected: {stats['safe_detected']}")
            if stats['total_checks'] > 0:
                malicious_percentage = (stats['malicious_detected'] / stats['total_checks']) * 100
                print(f"Malicious URL Percentage: {malicious_percentage:.2f}%")

        elif action == '5':  
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            export_file = f'url_analysis_log_{timestamp}.csv'
            try:
                with open(export_file, 'w') as f:
                    f.write("timestamp,url,classification,detection_method\n")
                    for entry in malicious_log:
                        f.write(f"{entry['timestamp']},{entry['url']},malicious,{entry['detection_method']}\n")
                    for entry in safe_log:
                        f.write(f"{entry['timestamp']},{entry['url']},safe,{entry['detection_method']}\n")
                print(colored(f"Logs exported successfully to {export_file}", "green"))
            except Exception as e:
                print(colored(f"Error exporting logs: {e}", "red"))

        elif action == '6': 
            urls_input = input("Enter multiple URLs (separated by commas): ").strip()
            if urls_input:
                urls_to_check = [url.strip() for url in urls_input.split(',')]
                print(f"\nAnalyzing {len(urls_to_check)} URLs...")
                
                for url in urls_to_check:
                    result = classifier.classification_of_url(url)
                    timestamp = datetime.datetime.now()
                    stats['total_checks'] += 1
                    
                    if result == "malicious link":
                        stats['malicious_detected'] += 1
                        print(f"{url}: {colored('malicious link', 'red')}")
                        malicious_log.append({
                            'url': url,
                            'timestamp': timestamp,
                            'detection_method': 'batch_analysis'
                        })
                    else:
                        stats['safe_detected'] += 1
                        print(f"{url}: {colored('non-malicious link', 'green')}")
                        safe_log.append({
                            'url': url,
                            'timestamp': timestamp,
                            'detection_method': 'batch_analysis'
                        })

        elif action == '7': 
            session_duration = datetime.datetime.now() - stats['session_start']
            print("\nSession Summary:")
            print(f"Session Duration: {session_duration}")
            print(f"Total URLs Analyzed: {stats['total_checks']}")
            print(f"Malicious URLs Detected: {stats['malicious_detected']}")
            print(f"Safe URLs Detected: {stats['safe_detected']}")
            print(colored("\nThank you for using the URL Malicious Detector. Goodbye!", "green"))
            break

        else:
            print(colored("Invalid option. Please choose a number between 1 and 7.", "red"))

        print(colored("------------------------------------------------------------------------", "cyan"))

if __name__ == "__main__":
    main()