export const REPO: string;
export const REPO_URL: string;
export const BRANCH: string;
export const SEASON: {
  name: string;
  years: string;
  rounds: { id: string; name: string; dates: string; images: string[] }[];
};
export const CHECKLISTS: {
  id: string;
  image: string;
  name: string;
  short: string;
  family: 'windows' | 'linux' | 'freebsd';
  blurb: string;
  script: string;
}[];
export const LEARNING_PATH: { path: string; label: string; minutes: number }[];
export const SCRIPTS: {
  id: string;
  name: string;
  file: string;
  config: string | null;
  worksOn: string;
  language: string;
  tested: string;
  testedLevel: 'tested' | 'partial' | 'untested';
  run: string;
}[];
