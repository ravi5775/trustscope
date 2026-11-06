/** Frequently impersonated brands and their official registrable domains. */
export interface Brand {
  name: string;
  token: string;
  official: string[];
}

export const BRANDS: Brand[] = [
  { name: "Google", token: "google", official: ["google.com", "google.co.in", "google.co.uk", "youtube.com", "gmail.com", "goo.gl"] },
  { name: "PayPal", token: "paypal", official: ["paypal.com", "paypal.me"] },
  { name: "Apple", token: "apple", official: ["apple.com", "icloud.com"] },
  { name: "Microsoft", token: "microsoft", official: ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com", "azure.com"] },
  { name: "Outlook", token: "outlook", official: ["outlook.com", "live.com", "office.com", "microsoft.com"] },
  { name: "Office 365", token: "office365", official: ["office.com", "microsoft.com"] },
  { name: "Amazon", token: "amazon", official: ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "aws.amazon.com", "amazonaws.com"] },
  { name: "Facebook", token: "facebook", official: ["facebook.com", "fb.com", "meta.com"] },
  { name: "Instagram", token: "instagram", official: ["instagram.com"] },
  { name: "WhatsApp", token: "whatsapp", official: ["whatsapp.com", "whatsapp.net"] },
  { name: "Netflix", token: "netflix", official: ["netflix.com"] },
  { name: "LinkedIn", token: "linkedin", official: ["linkedin.com"] },
  { name: "GitHub", token: "github", official: ["github.com", "github.io", "githubusercontent.com"] },
  { name: "Dropbox", token: "dropbox", official: ["dropbox.com"] },
  { name: "DocuSign", token: "docusign", official: ["docusign.com", "docusign.net"] },
  { name: "Chase", token: "chase", official: ["chase.com"] },
  { name: "Wells Fargo", token: "wellsfargo", official: ["wellsfargo.com"] },
  { name: "Bank of America", token: "bankofamerica", official: ["bankofamerica.com"] },
  { name: "Coinbase", token: "coinbase", official: ["coinbase.com"] },
  { name: "Binance", token: "binance", official: ["binance.com"] },
  { name: "MetaMask", token: "metamask", official: ["metamask.io"] },
  { name: "SBI", token: "onlinesbi", official: ["onlinesbi.sbi", "sbi.co.in", "onlinesbi.com"] },
  { name: "HDFC Bank", token: "hdfcbank", official: ["hdfcbank.com"] },
  { name: "ICICI Bank", token: "icicibank", official: ["icicibank.com"] },
  { name: "Paytm", token: "paytm", official: ["paytm.com"] },
  { name: "Flipkart", token: "flipkart", official: ["flipkart.com"] },
  { name: "Steam", token: "steamcommunity", official: ["steamcommunity.com", "steampowered.com"] },
];
