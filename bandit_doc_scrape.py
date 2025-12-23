import requests
from bs4 import BeautifulSoup

def scrape_bandit_docs(url: str):
    if not url:
        return "No documentation URL provided."
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        article = soup.find("div", itemprop="articleBody")
        if not article:
            return f"docs not found"
        allowed_tags = article.find_all(["h1", "h2", "h3"])
        paragraphs = "\n".join([p.get_text(strip=True) for p in article.find_all("p") if not p.find_parent("li") and not p.has_attr("class")])
        headings = "\n".join(tag.get_text(strip=True) for tag in allowed_tags)
        content = paragraphs+headings
        if content:
            print('content section returned')
            return content
    except Exception as e:
        return f"Failed to scrape Bandit docs: {str(e)}"


