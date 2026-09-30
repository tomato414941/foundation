import { Template } from '@fedify/uri-template';

// Parsing, escaping, reserved expansion and prefix lengths belong to RFC 6570.
export const uriTemplate = text => new Template(text);
export const templateVariables = template => [...new Set(template.tokens.filter(token => token.kind === 'expression').flatMap(token => token.vars.map(variable => variable.name)))];
