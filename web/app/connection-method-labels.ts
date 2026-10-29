import type { TFunction } from 'i18next';

const labels: Record<string, string> = {
  'Connect in browser': 'connectInBrowser',
  'Connect with app credentials': 'connectWithApp',
  'Enter API key': 'enterApiKey',
  'Enter Admin API key': 'enterAdminApiKey',
  'Enter access token': 'enterAccessToken',
  'Enter API token': 'enterApiToken',
  'Enter project token': 'enterProjectToken',
  'Enter proxy token': 'enterProxyToken',
  'Enter bot token': 'enterBotToken',
  'Enter integration secret': 'enterIntegrationSecret',
  'Enter credentials': 'enterCredentials',
  'Enter S3 credentials': 'enterS3Credentials',
  'Enter Robot credentials': 'enterRobotCredentials',
  'Enter service account key': 'enterServiceAccountKey',
  'Assume IAM role': 'assumeIamRole',
  'Authorize through Flash': 'authorizeThroughFlash',
  'AWS authentication': 'awsAuthentication',
  'Bearer token': 'httpBearer',
  'Basic authentication': 'httpBasic',
  'API key in header': 'httpHeaderKey',
  'API key in query': 'httpQueryKey',
  'URL without authentication': 'httpUrlOnly',
};

export function connectionMethodName(name: string, t: TFunction, serviceName?: string): string {
  const separator = name.lastIndexOf(' · ');
  if (separator < 0) return labels[name] ? t(labels[name]!) : name;
  const prefix = name.slice(0, separator), key = labels[name.slice(separator + 3)];
  if (!key) return name;
  return prefix === serviceName ? t(key) : prefix + ' · ' + t(key);
}
