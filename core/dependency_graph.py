"""
Dependency Graph Analyzer
Builds and analyzes the dependency tree.
Calculates blast radius, identifies critical nodes,
and detects dependency confusion risks.
"""

import requests
from config.settings import NPM_REGISTRY_URL, PYPI_REGISTRY_URL, SCAN_TIMEOUT_SECONDS

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False


class DependencyGraphAnalyzer:
    """
    Builds dependency graphs and analyzes them for security risks.
    """

    def __init__(self):
        if HAS_NETWORKX:
            self.graph = nx.DiGraph()
        else:
            self.graph = None
            self.adjacency = {}  # Fallback: simple adjacency list

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SupplyChainGuard/1.0"})
        self.scanned_packages = set()
        self.package_metadata = {}

    # ──────────────────────────────────────────────
    # PUBLIC API
    # ──────────────────────────────────────────────

    def analyze(self, package_name, ecosystem="npm", max_depth=3):
        """
        Build dependency graph and run all analyses.
        """
        # Reset state
        if HAS_NETWORKX:
            self.graph = nx.DiGraph()
        else:
            self.adjacency = {}
        self.scanned_packages = set()
        self.package_metadata = {}

        # Build the tree
        self._build_tree(package_name, ecosystem, current_depth=0,
                         max_depth=max_depth)

        result = {
            "root_package": package_name,
            "ecosystem": ecosystem,
            "total_dependencies": self._get_node_count() - 1,
            "max_depth_reached": max_depth,
            "dependency_list": list(self.scanned_packages),
            "critical_nodes": self._find_critical_nodes(),
            "blast_radius": self._calculate_blast_radius(package_name),
            "depth_analysis": self._analyze_depth(),
            "risk_score": 0,
            "risk_factors": []
        }

        # Calculate risk
        risk_score = 0
        risk_factors = []

        # Deep dependency tree risk
        total_deps = result["total_dependencies"]
        if total_deps > 50:
            risk_score += 20
            risk_factors.append(
                f"Very large dependency tree: {total_deps} packages"
            )
        elif total_deps > 20:
            risk_score += 10
            risk_factors.append(
                f"Large dependency tree: {total_deps} packages"
            )

        # Critical nodes risk
        critical = result["critical_nodes"]
        if critical:
            risk_score += len(critical) * 5
            risk_factors.append(
                f"{len(critical)} critical node(s) that many packages depend on"
            )

        result["risk_score"] = min(risk_score, 100)
        result["risk_factors"] = risk_factors

        return result

    # ──────────────────────────────────────────────
    # TREE BUILDING
    # ──────────────────────────────────────────────

    def _build_tree(self, package_name, ecosystem, current_depth, max_depth):
        """Recursively build dependency tree"""
        if current_depth >= max_depth:
            return
        if package_name in self.scanned_packages:
            return

        self.scanned_packages.add(package_name)

        # Fetch dependencies
        deps = self._fetch_dependencies(package_name, ecosystem)

        if not deps:
            return

        for dep_name in deps:
            # Add edge
            if HAS_NETWORKX:
                self.graph.add_edge(package_name, dep_name)
                self.graph.nodes[dep_name]["depth"] = current_depth + 1
            else:
                if package_name not in self.adjacency:
                    self.adjacency[package_name] = []
                self.adjacency[package_name].append(dep_name)

            # Recurse (limit to avoid API overload)
            if len(self.scanned_packages) < 100:
                self._build_tree(dep_name, ecosystem,
                                 current_depth + 1, max_depth)

    def _fetch_dependencies(self, package_name, ecosystem):
        """Fetch direct dependencies for a package"""
        try:
            if ecosystem == "npm":
                url = f"{NPM_REGISTRY_URL}/{package_name}/latest"
                resp = self.session.get(url, timeout=SCAN_TIMEOUT_SECONDS)
                if resp.status_code == 200:
                    data = resp.json()
                    return list(data.get("dependencies", {}).keys())

            elif ecosystem == "pypi":
                url = f"{PYPI_REGISTRY_URL}/{package_name}/json"
                resp = self.session.get(url, timeout=SCAN_TIMEOUT_SECONDS)
                if resp.status_code == 200:
                    data = resp.json()
                    requires = data.get("info", {}).get("requires_dist", [])
                    if requires:
                        deps = []
                        for req in requires:
                            name = req.split(";")[0].split("(")[0].split(
                                ">")[0].split("<")[0].split("=")[0].split(
                                "!")[0].strip()
                            if name:
                                deps.append(name)
                        return deps

        except Exception:
            pass

        return []

    # ──────────────────────────────────────────────
    # ANALYSIS METHODS
    # ──────────────────────────────────────────────

    def _get_node_count(self):
        """Get total number of nodes in graph"""
        if HAS_NETWORKX:
            return self.graph.number_of_nodes()
        else:
            all_nodes = set(self.adjacency.keys())
            for deps in self.adjacency.values():
                all_nodes.update(deps)
            return len(all_nodes)

    def _find_critical_nodes(self):
        """
        Find packages that are single points of failure.
        Uses betweenness centrality if networkx available.
        """
        if HAS_NETWORKX and self.graph.number_of_nodes() > 2:
            try:
                centrality = nx.betweenness_centrality(self.graph)
                critical = [
                    {"package": node, "centrality": round(score, 4)}
                    for node, score in centrality.items()
                    if score > 0.2
                ]
                critical.sort(key=lambda x: x["centrality"], reverse=True)
                return critical[:10]
            except Exception:
                return []
        else:
            # Fallback: find nodes with most dependents
            dependent_count = {}
            for parent, children in self.adjacency.items():
                for child in children:
                    dependent_count[child] = dependent_count.get(child, 0) + 1

            critical = [
                {"package": pkg, "dependent_count": count}
                for pkg, count in dependent_count.items()
                if count > 2
            ]
            critical.sort(key=lambda x: x["dependent_count"], reverse=True)
            return critical[:10]

    def _calculate_blast_radius(self, package_name):
        """
        How many packages are affected if this one is compromised?
        """
        if HAS_NETWORKX and package_name in self.graph:
            try:
                descendants = nx.descendants(self.graph, package_name)
                total = self.graph.number_of_nodes()
                return {
                    "affected_packages": list(descendants),
                    "affected_count": len(descendants),
                    "total_packages": total,
                    "percentage": round(
                        len(descendants) / max(total, 1) * 100, 2
                    )
                }
            except Exception:
                pass

        return {
            "affected_packages": [],
            "affected_count": 0,
            "total_packages": self._get_node_count(),
            "percentage": 0.0
        }

    def _analyze_depth(self):
        """Analyze dependency tree depth"""
        if HAS_NETWORKX and self.graph.number_of_nodes() > 0:
            try:
                # Find longest path
                longest = nx.dag_longest_path_length(self.graph)
                return {
                    "max_depth": longest,
                    "is_deep": longest > 5,
                    "warning": "Deep dependency tree increases attack surface"
                              if longest > 5 else None
                }
            except Exception:
                pass

        # Fallback: estimate depth
        return {
            "max_depth": len(self.scanned_packages),
            "is_deep": len(self.scanned_packages) > 20,
            "warning": None
        }

    def get_graph_data(self):
        """
        Export graph data for frontend visualization.
        Returns nodes and edges format compatible with React.
        """
        nodes = []
        edges = []

        if HAS_NETWORKX:
            for node in self.graph.nodes():
                nodes.append({
                    "id": node,
                    "label": node,
                    "depth": self.graph.nodes[node].get("depth", 0)
                })

            for source, target in self.graph.edges():
                edges.append({
                    "source": source,
                    "target": target
                })
        else:
            all_nodes = set(self.adjacency.keys())
            for deps in self.adjacency.values():
                all_nodes.update(deps)

            for node in all_nodes:
                nodes.append({"id": node, "label": node, "depth": 0})

            for parent, children in self.adjacency.items():
                for child in children:
                    edges.append({"source": parent, "target": child})

        return {"nodes": nodes, "edges": edges}