import type { TFunction } from 'i18next';

const labels: Record<string, string> = {
  'Connect in browser': 'connectInBrowser',
  'Connect with app credentials': 'connectWithApp',
  'Enter API key': 'enterApiKey',
  'Enter access token': 'enterAccessToken',
  'Enter API token': 'enterApiToken',
  'Enter bot token': 'enterBotToken',
  'Enter integration secret': 'enterIntegrationSecret',
  'Enter credentials': 'enterCredentials',
};

export function connectionMethodName(name: string, t: TFunction, serviceName?: string): string {
  const separator = name.lastIndexOf(' · ');
  if (separator < 0) return name;
  const prefix = name.slice(0, separator), key = labels[name.slice(separator + 3)];
  if (!key) return name;
  return prefix === serviceName ? t(key) : prefix + ' · ' + t(key);
}
