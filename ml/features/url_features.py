import re
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from collections import Counter
import string


class URLFeatureExtractor:
    """
    Extracts features from URLs for ML-based threat detection.
    This pipeline works for both training and inference.
    """

    # Suspicious keywords often found in malicious URLs
    SUSPICIOUS_KEYWORDS = [
        'login', 'signin', 'account', 'bank', 'secure', 'verify',
        'update', 'confirm', 'wallet', 'crypto', 'bitcoin', 'password',
        'credential', 'auth', 'authentication', 'reset', 'recover',
        'admin', 'administrator', 'hack', 'crack', 'free', 'download',
        'exe', 'zip', 'rar', 'torrent', 'phish', 'malware', 'virus',
        'trojan', 'spyware', 'keylog', 'steal', 'fake', 'scam'
    ]

    def __init__(self):
        self.feature_names = None

    def extract_features(self, urls):
        """
        Extract features from a list of URLs.

        Args:
            urls: List of URL strings or pandas Series

        Returns:
            DataFrame with extracted features
        """
        if isinstance(urls, pd.Series):
            urls = urls.tolist()

        features = []
        for url in urls:
            features.append(self._extract_single_url_features(url))

        df = pd.DataFrame(features)
        self.feature_names = df.columns.tolist()
        return df

    def _extract_single_url_features(self, url):
        """
        Extract features from a single URL.
        """
        if not isinstance(url, str):
            url = str(url)

        # Parse URL with error handling
        try:
            parsed = urlparse(url if '://' in url else f'http://{url}')
        except (ValueError, Exception):
            # If URL parsing fails, use a default parsed object
            parsed = urlparse('http://example.com')

        features = {}

        # Basic length features
        features['url_length'] = len(url)
        features['hostname_length'] = len(parsed.netloc)
        features['path_length'] = len(parsed.path)
        features['query_length'] = len(parsed.query)
        features['fragment_length'] = len(parsed.fragment)

        # Character counts
        features['dot_count'] = url.count('.')
        features['dash_count'] = url.count('-')
        features['underscore_count'] = url.count('_')
        features['question_count'] = url.count('?')
        features['equals_count'] = url.count('=')
        features['ampersand_count'] = url.count('&')
        features['percent_count'] = url.count('%')
        features['hash_count'] = url.count('#')
        features['slash_count'] = url.count('/')
        features['at_count'] = url.count('@')
        features['plus_count'] = url.count('+')
        features['asterisk_count'] = url.count('*')

        # Digit and letter counts
        features['digit_count'] = sum(c.isdigit() for c in url)
        features['letter_count'] = sum(c.isalpha() for c in url)
        features['special_char_count'] = sum(not c.isalnum() for c in url)

        # Protocol features
        features['has_http'] = 1 if url.startswith('http://') else 0
        features['has_https'] = 1 if url.startswith('https://') else 0
        features['has_protocol'] = 1 if '://' in url else 0

        # Domain features
        features['has_www'] = 1 if 'www.' in parsed.netloc else 0
        features['has_ip'] = 1 if self._has_ip_address(url) else 0

        # Subdomain count
        domain = parsed.netloc.replace('www.', '')
        subdomains = domain.split('.')
        features['subdomain_count'] = max(0, len(subdomains) - 2)

        # Path depth
        path_parts = [p for p in parsed.path.split('/') if p]
        features['path_depth'] = len(path_parts)

        # Query parameter count
        if parsed.query:
            features['query_param_count'] = len(parsed.query.split('&'))
        else:
            features['query_param_count'] = 0

        # File extension
        if '.' in parsed.path:
            extension = parsed.path.split('.')[-1].lower()
            features['has_exe'] = 1 if extension == 'exe' else 0
            features['has_zip'] = 1 if extension == 'zip' else 0
            features['has_rar'] = 1 if extension == 'rar' else 0
            features['has_php'] = 1 if extension == 'php' else 0
            features['has_html'] = 1 if extension in ['html', 'htm'] else 0
        else:
            features['has_exe'] = 0
            features['has_zip'] = 0
            features['has_rar'] = 0
            features['has_php'] = 0
            features['has_html'] = 0

        # Port presence
        features['has_port'] = 1 if ':' in parsed.netloc and ']' not in parsed.netloc.split(':')[-1] else 0

        # Suspicious keyword count
        features['suspicious_keyword_count'] = self._count_suspicious_keywords(url)

        # Entropy (character complexity)
        features['entropy'] = self._calculate_entropy(url)

        # Digit ratio
        if len(url) > 0:
            features['digit_ratio'] = features['digit_count'] / len(url)
        else:
            features['digit_ratio'] = 0

        # Special character ratio
        if len(url) > 0:
            features['special_char_ratio'] = features['special_char_count'] / len(url)
        else:
            features['special_char_ratio'] = 0

        # Uppercase letter count
        features['uppercase_count'] = sum(c.isupper() for c in url)

        # Lowercase letter count
        features['lowercase_count'] = sum(c.islower() for c in url)

        # Repeated character count (consecutive)
        features['repeated_char_count'] = self._count_repeated_chars(url)

        # Numeric ratio in domain
        domain_part = parsed.netloc
        if len(domain_part) > 0:
            features['domain_digit_ratio'] = sum(c.isdigit() for c in domain_part) / len(domain_part)
        else:
            features['domain_digit_ratio'] = 0

        return features

    def _has_ip_address(self, url):
        """Check if URL contains an IP address."""
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return bool(re.search(ip_pattern, url))

    def _count_suspicious_keywords(self, url):
        """Count suspicious keywords in URL."""
        url_lower = url.lower()
        count = 0
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in url_lower:
                count += 1
        return count

    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text."""
        if not text:
            return 0

        counts = Counter(text)
        total = len(text)
        entropy = 0

        for count in counts.values():
            probability = count / total
            if probability > 0:
                entropy -= probability * np.log2(probability)

        return entropy

    def _count_repeated_chars(self, text):
        """Count consecutive repeated characters."""
        if not text:
            return 0

        count = 0
        for i in range(1, len(text)):
            if text[i] == text[i-1]:
                count += 1

        return count

    def get_feature_names(self):
        """Return the list of feature names."""
        if self.feature_names is None:
            # Extract from a sample URL to get feature names
            sample_features = self._extract_single_url_features("http://example.com/path?query=value")
            self.feature_names = list(sample_features.keys())
        return self.feature_names


def extract_features_from_dataframe(df, url_column='url'):
    """
    Convenience function to extract features from a DataFrame.

    Args:
        df: DataFrame containing URLs
        url_column: Name of the column containing URLs

    Returns:
        DataFrame with features, DataFrame with labels (if present)
    """
    extractor = URLFeatureExtractor()

    # Extract features
    features_df = extractor.extract_features(df[url_column])

    # Get labels if available
    if 'type' in df.columns:
        labels_df = df[['type']].copy()
        return features_df, labels_df
    else:
        return features_df, None


if __name__ == "__main__":
    # Test the feature extractor
    test_urls = [
        "http://example.com",
        "https://www.google.com/search?q=test",
        "http://192.168.1.1/admin/login",
        "phishing-site.com/login.php",
        "http://example.com/path/to/file.exe",
        "https://secure-bank.com/signin?account=123"
    ]

    extractor = URLFeatureExtractor()
    features = extractor.extract_features(test_urls)

    print("Feature extraction test:")
    print(f"Number of features: {len(features.columns)}")
    print(f"Feature names: {features.columns.tolist()}")
    print("\nSample features:")
    print(features.head())
