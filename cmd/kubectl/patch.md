application/json-patch+json、application/merge-patch+json、application/strategic-merge-patch+json、application/apply-patch+yaml的区别

```
application/json-patch+json：使用 JSON Patch 格式，这是一个基于 JSON 的格式，用于描述如何将一个 JSON 文档转换为另一个 JSON 文档。它支持添加、删除、替换和移动操作，可以用于更新任何 JSON 格式的 Kubernetes 资源。

application/merge-patch+json：使用合并补丁（Merge Patch）格式，这是一种基于 JSON 的格式，用于将两个 JSON 文档合并成一个。它支持部分更新，即只更新需要更新的字段，其他字段保持不变。它可以用于更新任何 JSON 格式的 Kubernetes 资源。

application/strategic-merge-patch+json：使用战略合并补丁（Strategic Merge Patch）格式，这是一种基于 JSON 的格式，用于将两个 JSON 文档合并成一个，并且支持按照特定策略合并字段。
    它可以用于更新特定类型的 Kubernetes 资源，例如 Deployment、ReplicaSet、StatefulSet 等。

application/apply-patch+yaml：使用 Apply Patch 格式，这是一种基于 YAML 的格式，用于描述如何将一个 YAML 文档转换为另一个 YAML 文档。它支持添加、删除、替换和移动操作，可以用于更新任何 YAML 格式的 Kubernetes 资源。
```