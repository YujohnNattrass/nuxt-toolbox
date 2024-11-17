import { HTMLRewriter } from 'https://raw.githubusercontent.com/worker-tools/html-rewriter/master/index.ts';
import { randomBytes } from 'node:crypto';
const handler = async (request, context) => {
    const response = await context.next(request);
    console.log(`invoking edge function! ${request.url}`);

    // for debugging which routes use this edge function
    response.headers.set('x-debug-csp-nonce', 'invoked');

    // const isHTMLResponse = response.headers.get('content-type')?.startsWith('text/html');
    // const shouldTransformResponse = isHTMLResponse;
    // if (!shouldTransformResponse) {
    //     console.log(`Unnecessary invocation for ${request.url}`, {
    //         method: request.method,
    //         'content-type': response.headers.get('content-type')
    //     });
    //     return response;
    // }

    let header = 'content-security-policy';

    // CSP_NONCE_DISTRIBUTION is a number from 0 to 1,
    // but 0 to 100 is also supported, along with a trailing %
    // @ts-ignore
    const distribution = Netlify.env.get('CSP_NONCE_DISTRIBUTION');
    if (!!distribution) {
        const threshold =
            distribution.endsWith('%') || parseFloat(distribution) > 1
                ? Math.max(parseFloat(distribution) / 100, 0)
                : Math.max(parseFloat(distribution), 0);
        const random = Math.random();
        // if a roll of the dice is greater than our threshold...
        if (random > threshold && threshold <= 1) {
            if (header === 'content-security-policy') {
                // if the real CSP is set, then change to report only
                header = 'content-security-policy-report-only';
            } else {
                // if the CSP is set to report-only, return unadulterated response
                return response;
            }
        }
    }

    const nonce = randomBytes(24).toString('base64');
    // `'strict-dynamic'` allows scripts to be loaded from trusted scripts
    // when `'strict-dynamic'` is present, `'unsafe-inline' 'self' https: http:` is ignored by browsers
    // `'unsafe-inline' 'self' https: http:` is a compat check for browsers that don't support `strict-dynamic`
    // https://content-security-policy.com/strict-dynamic/
    const rules = [`'nonce-${nonce}'`, `'strict-dynamic'`, `'unsafe-inline'`, `'self'`, `https:`, `http:`].filter(
        Boolean
    );
    const scriptSrc = `script-src ${rules.join(' ')}`;
    const reportUri = `report-uri ${'/.netlify/functions/__csp-violations'}`;

    const csp = response.headers.get(header);
    if (csp) {
        const directives = csp
            .split(';')
            .map((directive) => {
                // prepend our rules for any existing directives
                const d = directive.trim();
                // intentionally add trailing space to avoid mangling `script-src-elem`
                if (d.startsWith('script-src ')) {
                    // append with trailing space to include any user-supplied values
                    // https://github.com/netlify/plugin-csp-nonce/issues/72
                    return d.replace('script-src ', `${scriptSrc} `).trim();
                }
                // intentionally omit report-uri: theirs should take precedence
                return d;
            })
            .filter(Boolean);
        // push our rules if the directives don't exist yet
        if (!directives.find((d) => d.startsWith('script-src '))) {
            directives.push(scriptSrc);
        }
        if (!directives.find((d) => d.startsWith('report-uri'))) {
            directives.push(reportUri);
        }
        const value = directives.join('; ');
        response.headers.set(header, value);
    } else {
        // make a new ruleset of directives if no CSP present
        const value = [scriptSrc, reportUri].join('; ');
        response.headers.set(header, value);
    }

    const querySelectors = ['script', 'link[rel="preload"][as="script"]'];
    let transformed;
    try {
        transformed = await new HTMLRewriter()
            .on(querySelectors.join(','), {
                element(element) {
                    element.setAttribute('nonce', nonce);
                }
            })
            .transform(response);
        console.log(`## after TRANSFORMER ##`);
        return transformed
    } catch (e) {
        console.log(`WHAT IS THE ERROR`, e);
    }

    // console.log(`## transformed`, transformed);
    // const resBody = await transformed.bytes();
    // const newRes = new Response(resBody, response);
    // transformed.pipe(newRes)
    // return newRes
};

export default handler;

