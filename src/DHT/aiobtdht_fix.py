"""
Monkey patch for aiobtdht to fix KeyError bug in routing_table/bucket.py

The bug: When removing nodes with negative rate, the code tries to pop a tuple (node, stat)
from the _nodes dictionary, but the dictionary keys are just node objects.

The fix: Extract the node object from the tuple before popping.
"""

def patch_aiobtdht():
    """Apply the fix to aiobtdht.routing_table.bucket.Bucket.add method"""
    try:
        from aiobtdht.routing_table.bucket import Bucket
        from aiobtdht.routing_table.node_stat import NodeStat
        
        # Store the original add method
        original_add = Bucket.add
        
        def fixed_add(self, node):
            """Fixed version of Bucket.add that properly unpacks the tuple when deleting nodes"""
            if not self.id_in_range(node.id):
                raise IndexError("Node id not in bucket range")

            if node in self._nodes:
                self._nodes[node].renew()
                return True
            elif len(self._nodes) < self._max_capacity:
                self._nodes[node] = NodeStat()
                return True
            else:
                can_delete = list(filter(lambda it: it[1].rate < 0, self._enum_nodes()))
                if can_delete:
                    # FIX: Unpack the tuple (node, stat) and only pop the node
                    for node_to_delete, _ in can_delete:
                        self._nodes.pop(node_to_delete)

                    return self.add(node)
                else:
                    return False
        
        # Replace the method
        Bucket.add = fixed_add
        return True
        
    except Exception as e:
        print(f"Warning: Failed to patch aiobtdht: {e}")
        return False


# Apply the patch when this module is imported
patch_aiobtdht()

