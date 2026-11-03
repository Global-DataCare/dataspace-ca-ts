// Flow contract: the offline CA repository exposes one locally resolvable rules graph without transferring private-key custody or deployment authority.
import assert from 'node:assert/strict'
import { access, readFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')

function relativeTargets(markdown) {
  return [...markdown.matchAll(/\[[^\]]+\]\(([^)]+)\)/gu)]
    .map(([, target]) => target)
    .filter((target) => !/^(?:https?:|mailto:|#)/u.test(target))
}

test('keeps repository-owned CA rules linked and locally resolvable', async () => {
  const agentsPath = resolve(repositoryRoot, 'AGENTS.md')
  const indexPath = resolve(repositoryRoot, 'docs/RULES_INDEX.md')
  const agents = await readFile(agentsPath, 'utf8')
  const index = await readFile(indexPath, 'utf8')

  assert.match(agents, /docs\/RULES_INDEX\.md/u)
  assert.match(index, /README\.md/u)
  assert.match(index, /dataspace-ca-ts-design\.md/u)
  assert.match(index, /static-trust-publication\.test\.js/u)

  for (const [path, markdown] of [[agentsPath, agents], [indexPath, index]]) {
    for (const target of relativeTargets(markdown)) {
      await access(resolve(dirname(path), target.split('#', 1)[0]))
    }
  }
})
