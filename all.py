from save_flows_addon import SaveResponses
from interceptor import URLInterceptor
from flow_actions import FlowActions
# from whatnot_pwn import RBACExploiter,FeatureGateEnabler

addons = [FlowActions(), SaveResponses(), URLInterceptor()]
