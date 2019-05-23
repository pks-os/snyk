import * as fs from 'fs';
import * as config from './config';

export const suggestionText =
  '\n\nWe noticed that there is a Dockerfile in the current directory.' +
  '\nConsider using Snyk to scan your docker images.' +
  '\n\nExample: $ snyk test --docker <image> --file=Dockerfile' +
  '\n\nTo remove this message in the future, please run `snyk config set disableSuggestions=true`';

export function shouldSuggestDocker(options) {
  const dateToStopDockerPromotion = Number(new Date('2019-01-01'));
  const dateNow = Date.now();
  try {
    return (!options.docker &&
      fs.existsSync('Dockerfile') &&
      (config.disableSuggestions !== 'true') &&
      (dateNow < dateToStopDockerPromotion));
  } catch (e) {
    return false;
  }
}
