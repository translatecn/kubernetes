import os

base = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src')
ls = set()
rs = [
    "bitbucket.org",
    # "github.com",
    "go.opencensus.io",
    "go.starlark.net",
    "golang.org",
    "gopkg.in",
    "sigs.k8s.io",
    "cloud.google.com",
    # "go.etcd.io",
    "go.opentelemetry.io",
    "go.uber.org",
    "google.golang.org",
    "k8s.io"
]

xxx='''/Users/acejilam/Desktop/kubernetes/go.mod:236:5: replace k8s.io/client-go/informers/events/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:247:5: replace k8s.io/api/rbac/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:280:5: replace k8s.io/client-go/kubernetes/typed/events/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:291:5: replace k8s.io/client-go/listers/admissionregistration/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:294:5: replace k8s.io/client-go/listers/certificates/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:311:5: replace k8s.io/code-generator/examples/MixedCase/apis/example/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:331:5: replace k8s.io/client-go/kubernetes/typed/authorization/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:335:5: replace k8s.io/client-go/listers/networking/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:346:5: replace k8s.io/api/apps/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:357:5: replace k8s.io/client-go/applyconfigurations/core/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:365:5: replace k8s.io/client-go/informers/autoscaling/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:366:5: replace k8s.io/client-go/applyconfigurations/policy/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:379:5: replace k8s.io/client-go/kubernetes/typed/core/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:394:5: replace k8s.io/api/coordination/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:416:5: replace k8s.io/code-generator/examples/crd/listers/example/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:428:5: replace k8s.io/client-go/kubernetes/typed/storage/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:431:5: replace k8s.io/apiserver/pkg/over_quota/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:434:5: replace k8s.io/api/core/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:443:5: replace k8s.io/apiserver/pkg/admission/plugin/webhook/config/apis/webhookadmission/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:446:5: replace k8s.io/client-go/listers/coordination/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:448:5: replace k8s.io/api/autoscaling/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:526:5: replace k8s.io/code-generator/examples/apiserver/listers/example/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:529:5: replace k8s.io/client-go/informers/apps/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:530:5: replace k8s.io/client-go/applyconfigurations/admissionregistration/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:533:5: replace k8s.io/client-go/listers/autoscaling/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:534:5: replace k8s.io/apiserver/pkg/apis/audit/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:539:5: replace github.com/containerd/cgroups/stats/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:546:5: replace k8s.io/client-go/kubernetes/typed/discovery/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:556:5: replace k8s.io/apiextensions-apiserver/examples/client-go/pkg/client/listers/cr/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:560:5: replace k8s.io/client-go/listers/apps/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:565:5: replace go.opentelemetry.io/proto/otlp/collector/trace/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:575:5: replace k8s.io/cri-api/pkg/apis/runtime/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:583:5: replace k8s.io/client-go/applyconfigurations/meta/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:585:5: replace k8s.io/apiextensions-apiserver/pkg/client/informers/externalversions/apiextensions/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:642:5: replace k8s.io/kube-aggregator/pkg/client/informers/externalversions/apiregistration/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:680:5: replace k8s.io/code-generator/examples/apiserver/informers/externalversions/example2/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:687:5: replace k8s.io/client-go/listers/storage/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:688:5: replace k8s.io/client-go/applyconfigurations/batch/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:697:5: replace k8s.io/client-go/applyconfigurations/discovery/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:706:5: replace k8s.io/api/admission/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:707:5: replace gopkg.in/square/go-jose.v2/json: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:728:5: replace k8s.io/code-generator/examples/apiserver/apis/example/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:733:5: replace k8s.io/kubelet/pkg/apis/pluginregistration/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:737:5: replace k8s.io/apimachinery/pkg/apis/meta/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:739:5: replace k8s.io/code-generator/examples/HyphenGroup/apis/example/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:759:5: replace github.com/google/cadvisor/third_party/containerd/api/services/version/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:774:5: replace k8s.io/client-go/listers/node/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:781:5: replace github.com/google/cadvisor/third_party/containerd/api/services/tasks/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:782:5: replace k8s.io/client-go/informers/storage/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:796:5: replace k8s.io/code-generator/examples/crd/clientset/versioned/typed/example2/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:808:5: replace k8s.io/api/node/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:810:5: replace k8s.io/client-go/applyconfigurations/scheduling/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:814:5: replace k8s.io/client-go/applyconfigurations/rbac/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:833:5: replace k8s.io/code-generator/examples/crd/apis/example/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:856:5: replace k8s.io/client-go/applyconfigurations/storage/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:871:5: replace k8s.io/client-go/pkg/apis/clientauthentication/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:885:5: replace k8s.io/client-go/applyconfigurations/apps/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:889:5: replace k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:903:5: replace k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:930:5: replace k8s.io/component-base/logs/api/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:946:5: replace k8s.io/client-go/tools/clientcmd/api/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:950:5: replace k8s.io/api/networking/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:957:5: replace k8s.io/client-go/informers/admissionregistration/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:975:5: replace k8s.io/code-generator/examples/HyphenGroup/clientset/versioned/typed/example/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1010:5: replace k8s.io/client-go/informers/coordination/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1014:5: replace k8s.io/client-go/informers/node/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1021:5: replace k8s.io/code-generator/examples/MixedCase/clientset/versioned/typed/example/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1025:5: replace k8s.io/pod-security-admission/admission/api/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1035:5: replace k8s.io/client-go/informers/policy/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1047:5: replace k8s.io/client-go/listers/rbac/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1055:5: replace k8s.io/kubelet/pkg/apis/credentialprovider/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1073:5: replace k8s.io/api/storage/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1075:5: replace k8s.io/client-go/listers/events/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1087:5: replace k8s.io/apiextensions-apiserver/examples/client-go/pkg/client/clientset/versioned/typed/cr/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1113:5: replace github.com/google/cadvisor/third_party/containerd/api/services/containers/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1115:5: replace k8s.io/client-go/listers/core/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1128:5: replace k8s.io/client-go/applyconfigurations/coordination/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1154:5: replace k8s.io/code-generator/examples/apiserver/clientset/versioned/typed/example2/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1174:5: replace k8s.io/code-generator/examples/crd/apis/example2/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1175:5: replace k8s.io/client-go/informers/networking/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1180:5: replace k8s.io/api/admissionregistration/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1185:5: replace k8s.io/kube-aggregator/pkg/client/listers/apiregistration/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1190:5: replace k8s.io/api/authentication/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1235:5: replace k8s.io/client-go/applyconfigurations/autoscaling/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1295:5: replace k8s.io/apiextensions-apiserver/examples/client-go/pkg/client/informers/externalversions/cr/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1324:5: replace gopkg.in/gcfg.v1/types: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1346:5: replace k8s.io/client-go/kubernetes/typed/rbac/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1355:5: replace k8s.io/code-generator/examples/crd/informers/externalversions/example/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1360:5: replace k8s.io/api/discovery/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1420:5: replace k8s.io/code-generator/examples/apiserver/listers/example2/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1425:5: replace k8s.io/client-go/kubernetes/typed/node/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1427:5: replace k8s.io/code-generator/examples/apiserver/apis/example2/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1436:5: replace k8s.io/client-go/kubernetes/typed/admissionregistration/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1439:5: replace k8s.io/apimachinery/pkg/apis/testapigroup/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1443:5: replace k8s.io/api/authorization/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1447:5: replace k8s.io/code-generator/examples/apiserver/apis/example3.io/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1498:5: replace k8s.io/code-generator/examples/apiserver/listers/example3.io/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1502:5: replace k8s.io/client-go/listers/scheduling/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1508:5: replace k8s.io/apiserver/pkg/apis/apiserver/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1510:5: replace k8s.io/code-generator/examples/crd/listers/example2/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1516:5: replace k8s.io/client-go/applyconfigurations/events/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1521:5: replace k8s.io/apiserver/pkg/apis/example2/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1523:5: replace k8s.io/client-go/applyconfigurations/node/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1526:5: replace k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/typed/apiregistration/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1528:5: replace k8s.io/code-generator/examples/crd/informers/externalversions/example2/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1529:5: replace k8s.io/api/policy/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1532:5: replace k8s.io/client-go/kubernetes/typed/certificates/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1547:5: replace k8s.io/kube-aggregator/pkg/client/clientset_generated/deprecated/typed/apiregistration/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1563:5: replace k8s.io/code-generator/examples/apiserver/informers/externalversions/example/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1582:5: replace k8s.io/apiextensions-apiserver/pkg/client/listers/apiextensions/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1609:5: replace k8s.io/client-go/listers/batch/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1624:5: replace k8s.io/code-generator/examples/crd/clientset/versioned/typed/example/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1626:5: replace k8s.io/client-go/kubernetes/typed/authentication/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1637:5: replace k8s.io/api/batch/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1678:5: replace k8s.io/client-go/informers/discovery/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1680:5: replace k8s.io/apiextensions-apiserver/examples/client-go/pkg/apis/cr/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1703:5: replace k8s.io/apiextensions-apiserver/pkg/client/clientset/deprecated/typed/apiextensions/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1749:5: replace k8s.io/code-generator/examples/MixedCase/informers/externalversions/example/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1766:5: replace k8s.io/client-go/applyconfigurations/certificates/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1809:5: replace k8s.io/client-go/listers/policy/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1819:5: replace k8s.io/controller-manager/config/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1825:5: replace k8s.io/api/certificates/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1834:5: replace k8s.io/api/events/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1835:5: replace k8s.io/client-go/kubernetes/typed/networking/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1837:5: replace k8s.io/client-go/informers/core/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1846:5: replace k8s.io/client-go/informers/rbac/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1850:5: replace k8s.io/client-go/listers/discovery/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1882:5: replace k8s.io/apiserver/pkg/admission/plugin/resourcequota/apis/resourcequota/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1885:5: replace k8s.io/client-go/informers/batch/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1889:5: replace go.opentelemetry.io/proto/otlp/trace/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1896:5: replace go.opentelemetry.io/proto/otlp/resource/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1917:5: replace k8s.io/apiserver/pkg/apis/example/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1956:5: replace k8s.io/client-go/kubernetes/typed/autoscaling/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1967:5: replace k8s.io/client-go/applyconfigurations/networking/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:1979:5: replace k8s.io/component-base/tracing/api/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2011:5: replace k8s.io/client-go/kubernetes/typed/apps/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2016:5: replace k8s.io/api/scheduling/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2037:5: replace k8s.io/code-generator/examples/HyphenGroup/listers/example/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2043:5: replace k8s.io/client-go/kubernetes/typed/scheduling/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2049:5: replace k8s.io/code-generator/examples/MixedCase/listers/example/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2058:5: replace go.opentelemetry.io/otel/semconv/v1.4.0: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2064:5: replace k8s.io/code-generator/examples/HyphenGroup/informers/externalversions/example/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2087:5: replace k8s.io/client-go/informers/scheduling/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2094:5: replace k8s.io/kube-aggregator/pkg/apis/apiregistration/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2096:5: replace gopkg.in/gcfg.v1/token: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2105:5: replace k8s.io/client-go/kubernetes/typed/coordination/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2110:5: replace k8s.io/code-generator/examples/apiserver/informers/externalversions/example3.io/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2140:5: replace github.com/google/cadvisor/info/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2143:5: replace k8s.io/code-generator/examples/apiserver/clientset/versioned/typed/example/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2149:5: replace go.opentelemetry.io/proto/otlp/common/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2164:5: replace k8s.io/apiserver/pkg/apis/config/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2176:5: replace k8s.io/client-go/kubernetes/typed/batch/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2190:5: replace go.opentelemetry.io/otel/semconv/v1.12.0: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2199:5: replace gopkg.in/gcfg.v1/scanner: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2216:5: replace k8s.io/code-generator/examples/apiserver/clientset/versioned/typed/example3.io/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2220:5: replace gopkg.in/square/go-jose.v2/cipher: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2230:5: replace k8s.io/client-go/informers/certificates/v1: invalid module path
/Users/acejilam/Desktop/kubernetes/go.mod:2234:5: replace k8s.io/client-go/kubernetes/typed/policy/v1: invalid module path
'''

xxxx = [item.split('replace')[-1].strip(' ')[:-21] for item in xxx.split('\n')]




for c, _dirs, files in os.walk(base):
    for name in files:
        if not name.endswith('.go'):
            continue
        with open(os.path.join(c, name), 'r', encoding='utf8') as f:

            for line in f.readlines():
                if not line.startswith('\t'):
                    continue
                ex = ""
                for item in rs:
                    if item in line:
                        ex = item
                        break
                if ex:
                    x = line.strip().split(' ')[-1].strip('"')
                    if x.startswith(ex):
                        if x.endswith(')') or x.endswith(','):
                            continue
                        ls.add(x)


for item in ls:
    if os.path.exists(f'./src/{item}'):
        if item in xxxx:
            continue
        print(f'{item} => ./staging/src/{item}')
#      	k8s.io/apimachinery => ./staging/src/k8s.io/apimachinery
#
